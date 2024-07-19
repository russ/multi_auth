class MultiAuth::Provider::X < MultiAuth::Provider
  def authorize_uri(scope = nil)
    request_token = consumer.get_request_token(redirect_uri)
    consumer.get_authorize_uri(request_token, redirect_uri)
  end

  def user(params : Hash(String, String))
    x_user = fetch_x_user(params["oauth_token"], params["oauth_verifier"])

    user = User.new(
      "x",
      x_user.id,
      x_user.name,
      x_user.raw_json.to_s,
      x_user.access_token.not_nil!
    )

    user.email = x_user.email
    user.nickname = x_user.screen_name
    user.location = x_user.location
    user.description = x_user.description
    user.image = x_user.profile_image_url
    if url = x_user.url
      user.urls = {"x" => url}
    end

    user
  end

  private class XUser
    include JSON::Serializable

    property raw_json : String?
    property access_token : OAuth::AccessToken?

    @[JSON::Field(converter: String::RawConverter)]
    property id : String

    property name : String
    property screen_name : String
    property location : String?
    property description : String?
    property url : String?
    property profile_image_url : String?
    property email : String?
  end

  private def fetch_x_user(oauth_token, oauth_verifier)
    request_token = OAuth::RequestToken.new(oauth_token, "")

    access_token = consumer.get_access_token(request_token, oauth_verifier)

    client = HTTP::Client.new("api.x.com", tls: true)
    access_token.authenticate(client, key, secret)

    raw_json = client.get("/1.1/account/verify_credentials.json?include_email=true").body

    XUser.from_json(raw_json).tap do |user|
      user.access_token = access_token
      user.raw_json = raw_json
    end
  end

  private def consumer
    @consumer ||= OAuth::Consumer.new("api.x.com", key, secret)
  end
end
