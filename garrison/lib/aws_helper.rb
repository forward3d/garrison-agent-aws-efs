module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= ENV['AWS_ACCOUNT_ID'] || Aws::STS::Client.new(region: 'us-east-1').get_caller_identity.account
    end

    def self.all_regions
      Aws::Partitions.partition('aws').service('EFS').regions
    end

    def self.available_engines_and_versions(efs)
      Logging.debug 'AWS SDK - Pulling all supported engines and versions'
      db_engine_versions = describe_db_engine_versions(efs)

      db_engine_versions.each_with_object({}) do |eav, hash|
        hash[eav.engine] ||= Hash.new
        hash[eav.engine][eav.engine_version] = eav.valid_upgrade_target
      end
    end

    private

    def self.describe_db_engine_versions(efs)
      Enumerator.new do |yielder|
        marker = ''

        loop do
          results = efs.describe_db_engine_versions(marker: marker)
          results.db_engine_versions.map { |item| yielder << item }

          if results.marker
            marker = results.marker
          else
            raise StopIteration
          end
        end
      end.lazy
    end

  end
end