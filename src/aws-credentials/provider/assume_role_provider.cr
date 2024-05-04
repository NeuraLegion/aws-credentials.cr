require "../sts_client"

module Aws::Credentials
  # Resolving credential via AWS Security Token Service(STS) as assume role.
  #
  # https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  class AssumeRoleProvider
    include Provider
    include CredentialsWithExpiration

    @last_credentials : Credentials? = nil

    def initialize(
      @role_arn : String,
      @role_session_name : String,
      @sts_client : STSClient,
      @duration : Time::Span? = nil,
      @policy : JSON::Any? = nil,
      @current_time_provider : Proc(Time) = ->{ Time.utc },
      logger : Log = ::Log.for("AWS.Credentials")
    )
      @logger = logger.for("AssumeRoleProvider")
    end

    def credentials : Credentials
      credentials = @last_credentials
      if !credentials
        @logger.debug { "No credentials are available, resolving new credentials" }
      elsif expired?(credentials, @current_time_provider)
        @logger.debug { "The credentials have expired, resolving new credentials" }
      else
        return credentials
      end

      @last_credentials = resolve_credentials
    end

    private def resolve_credentials
      @sts_client.assume_role @role_arn, @role_session_name, @duration, @policy
    end
  end
end
