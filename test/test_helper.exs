ExUnit.start()

if System.get_env("MOBILE_ID_TOKEN_INTEGRATION") != "1" do
  ExUnit.configure(exclude: [integration: true])
end
