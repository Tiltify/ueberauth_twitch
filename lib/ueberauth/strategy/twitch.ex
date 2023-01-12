defmodule Ueberauth.Strategy.Twitch do
  @moduledoc """
  Twitch Strategy for Überauth.

  Required Request Parameters:
  - client_id
  - redirect_uri
  - response_type :: must be "token"
  - scope :: https://dev.twitch.tv/docs/authentication/#scopes

  Optional
  force_verify
  state
  """

  use Ueberauth.Strategy
  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials

  @doc """
  Handles initial request for Twitch authentication.
  """

  def handle_request!(%Plug.Conn{params: %{"client_id" => nil}} = conn) do
    set_errors!(conn, [error("missing_client_id", "Twitch requires a client-id for api requests")])
  end

  def handle_request!(%Plug.Conn{params: %{"redirect_uri" => nil}} = conn) do
    set_errors!(conn, [error("missing_redirect_uri", "Twitch requires a redirect_uri")])
  end

  def handle_request!(conn) do
    opts =
      [
        client_id: UeberauthTwitch.client_id(),
        redirect_uri: callback_url(conn)
      ]
      |> with_state_param(conn)

    redirect!(conn, Ueberauth.Strategy.Twitch.OAuth.authorize_url!(opts))
  end

  @doc """
  Handles the callback from Twitch.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    %OAuth2.Client{token: token} = Ueberauth.Strategy.Twitch.OAuth.get_token!([code: code], opts)

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      conn
      |> store_token(token)
      |> fetch_user(token)
    end
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.twitch_user

    %Info{
      name: user["name"],
      email: user["email"],
      nickname: user["login"],
      description: user["description"],
      image: user["profile_image_url"],
      urls: %{Twitch: "http://www.twitch.tv/#{user["login"]}"}
    }
  end

  @doc """
  Includes the credentials from the response.
  """
  def credentials(conn) do
    token = conn.private.twitch_token

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      refresh_token: token.refresh_token,
      token: token.access_token,
      scopes: token.other_params["scope"],
      token_type: token.token_type
    }
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:twitch_token, nil)
    |> put_private(:twitch_user, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    conn.private.twitch_user["id"]
  end

  # Store the token for later use.
  @doc false
  defp store_token(conn, token) do
    put_private(conn, :twitch_token, token)
  end

  defp fetch_user(conn, token) do
    path = "https://api.twitch.tv/helix/users"
    resp = Ueberauth.Strategy.Twitch.OAuth.get(token, path)

    case resp do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: %{"data" => [user]}}}
      when status_code in 200..399 ->
        put_private(conn, :twitch_user, user)

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end
end
