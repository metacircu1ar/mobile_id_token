defmodule MobileIdToken.ConcurrencyCacheTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:google)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:google)
    end)

    :ok
  end

  test "concurrent verifications on empty cache all succeed" do
    client_id = "google-client-concurrent-success"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-concurrent-success"
      })

    task_count = 8
    parent = self()
    stub_name = {:google_jwks_concurrent_success, make_ref()}

    TokenHelpers.with_req_stub(
      stub_name,
      fn conn ->
        send(parent, :jwks_called)
        Req.Test.json(conn, %{"keys" => [jwk_map]})
      end,
      fn ->
        tasks =
          spawn_verify_tasks(task_count, stub_name, fn ->
            MobileIdToken.verify(:google, token, client_ids: [client_id])
          end)

        results = Enum.map(tasks, &Task.await(&1, 5_000))

        assert Enum.count(results, &match?({:ok, _}, &1)) == task_count
        assert_received :jwks_called
      end
    )
  end

  test "concurrent empty-cache requests can trigger multiple refresh calls" do
    client_id = "google-client-concurrent-fanout"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-concurrent-fanout"
      })

    task_count = 8
    parent = self()
    stub_name = {:google_jwks_concurrent_fanout, make_ref()}
    counter = :atomics.new(1, [])

    TokenHelpers.with_req_stub(
      stub_name,
      fn conn ->
        :atomics.add_get(counter, 1, 1)
        send(parent, :jwks_refresh_called)
        Process.sleep(75)
        Req.Test.json(conn, %{"keys" => [jwk_map]})
      end,
      fn ->
        tasks =
          spawn_verify_tasks(task_count, stub_name, fn ->
            MobileIdToken.verify(:google, token, client_ids: [client_id])
          end)

        results = Enum.map(tasks, &Task.await(&1, 5_000))
        refresh_calls = :atomics.get(counter, 1)

        assert Enum.count(results, &match?({:ok, _}, &1)) == task_count
        assert refresh_calls > 1

        for _ <- 1..refresh_calls do
          assert_received :jwks_refresh_called
        end
      end
    )
  end

  test "two concurrent empty-cache requests both refresh JWKS (current race behavior)" do
    client_id = "google-client-concurrent-two"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-concurrent-two"
      })

    task_count = 2
    stub_name = {:google_jwks_concurrent_two, make_ref()}
    counter = :atomics.new(1, [])

    TokenHelpers.with_req_stub(
      stub_name,
      fn conn ->
        :atomics.add_get(counter, 1, 1)
        Process.sleep(200)
        Req.Test.json(conn, %{"keys" => [jwk_map]})
      end,
      fn ->
        tasks =
          spawn_verify_tasks(task_count, stub_name, fn ->
            MobileIdToken.verify(:google, token, client_ids: [client_id])
          end)

        results = Enum.map(tasks, &Task.await(&1, 5_000))

        assert Enum.count(results, &match?({:ok, _}, &1)) == task_count
        # Pins the current no-single-flight behavior: two concurrent empty-cache
        # verifications each trigger refresh. If refresh de-dup is added later,
        # this assertion should be updated to expect 1.
        assert :atomics.get(counter, 1) == 2
      end
    )
  end

  defp spawn_verify_tasks(count, stub_name, verify_fun)
       when is_integer(count) and count > 0 and is_function(verify_fun, 0) do
    owner = self()

    tasks =
      for _ <- 1..count do
        Task.async(fn ->
          receive do
            :go -> :ok
          end

          verify_fun.()
        end)
      end

    Enum.each(tasks, fn %Task{pid: pid} ->
      :ok = Req.Test.allow(stub_name, owner, pid)
    end)

    Enum.each(tasks, fn %Task{pid: pid} ->
      send(pid, :go)
    end)

    tasks
  end
end
