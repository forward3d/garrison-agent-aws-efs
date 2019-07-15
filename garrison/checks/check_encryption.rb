module Garrison
  module Checks
    class CheckEncryption < Check

      def settings
        self.source ||= 'aws-efs'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
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

          not_encrypted.each do |filesystem|
            alert(
              name: 'Encryption Violation',
              target: filesystem.file_system_id,
              detail: 'encrypted: false',
              finding: filesystem.to_h.to_json,
              finding_id: "aws-efs-#{filesystem.file_system_id}-encryption",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/efs/home?region=#{region}#/filesystems:id=#{filesystem.file_system_id}"
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

          efs = Aws::EFS::Client.new(credentials: role_credentials, region: region)
        else
          efs = Aws::EFS::Client.new(region: region)
        end

        file_systems = efs.describe_file_systems.file_systems
        file_systems.select { |i| i.encrypted == false }
      rescue Aws::EFS::Errors::OptInRequired => e
        Logging.warn "#{region} - #{e.message}"
        return []
      rescue Aws::EFS::Errors::InvalidClientTokenId => e
        Logging.warn "#{region} - #{e.message}"
        return []
      end
    end
  end
end
