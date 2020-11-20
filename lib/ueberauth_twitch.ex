defmodule UeberauthTwitch do
  @moduledoc """
  Documentation for `UeberauthTwitch`.
  """

  @doc """
  """
  def client_id do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Twitch.OAuth)[:client_id]
  end

  def client_secret do
    Application.get_env(:ueberauth, Ueberauth.Strategy.Twitch.OAuth)[:client_secret]
  end
end
