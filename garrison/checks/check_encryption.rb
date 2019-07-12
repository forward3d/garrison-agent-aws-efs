module Garrison
  module Checks
    class CheckEncryption < Check

      def settings
        self.source ||= 'aws-efs'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:engines] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'efs' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          not_encrypted = unecrypted_efs(region)

          not_encrypted.each do |instance|
            alert(
              name: 'Encryption Violation',
              target: instance.db_instance_identifier,
              detail: 'storage_encrypted: false',
              finding: instance.to_h.to_json,
              finding_id: "aws-efs-#{instance.db_instance_identifier}-encryption",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/efs/home?region=#{region}#dbinstance:id=#{instance.db_instance_identifier}"
                }
              ],
              key_values: [
                {
                  key: 'aws-region',
                  value: region
                }
              ]
            )
          end
        end
      end

      private

      def unecrypted_efs(region)
        if ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN']
          role_credentials = Aws::AssumeRoleCredentials.new(
            client: Aws::STS::Client.new(region: region),
            role_arn: ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN'],
            role_session_name: 'garrison-agent-efs'
          )

          efs = Aws::efs::Client.new(credentials: role_credentials, region: region)
        else
          efs = Aws::efs::Client.new(region: region)
        end

        db_instances = efs.describe_db_instances.db_instances

        if options[:engines] && options[:engines] != 'all'
          db_instances.select! { |i| options[:engines].include?(i.engine) }
        end

        db_instances.select { |i| i.storage_encrypted == false }
      rescue Aws::efs::Errors::OptInRequired => e
        Logging.warn "#{region} - #{e.message}"
        return []
      rescue Aws::efs::Errors::InvalidClientTokenId => e
        Logging.warn "#{region} - #{e.message}"
        return []
      end
    end
  end
end