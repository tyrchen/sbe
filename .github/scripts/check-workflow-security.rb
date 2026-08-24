# frozen_string_literal: true

require "yaml"

WORKFLOW_GLOB = File.expand_path("../workflows/*.{yml,yaml}", __dir__)
ACTION_FILE = File.expand_path("../../action.yml", __dir__)
READ_ONLY = { "contents" => "read" }.freeze
RELEASE_JOB_PERMISSIONS = {
  "create-release" => { "contents" => "write" },
  "build" => {
    "contents" => "write",
    "id-token" => "write",
    "attestations" => "write"
  },
  "publish-release" => { "contents" => "write" }
}.freeze

def fail_check(message)
  warn "workflow security check failed: #{message}"
  exit 1
end

def load_yaml(path)
  YAML.safe_load(File.read(path), aliases: false) || {}
rescue Psych::Exception => error
  fail_check("#{path}: invalid YAML: #{error.message}")
end

def each_uses(value, location, &block)
  case value
  when Hash
    value.each do |key, child|
      child_location = "#{location}.#{key}"
      block.call(child, child_location) if key == "uses"
      each_uses(child, child_location, &block)
    end
  when Array
    value.each_with_index { |child, index| each_uses(child, "#{location}[#{index}]", &block) }
  end
end

workflow_paths = Dir[WORKFLOW_GLOB].sort
fail_check("no workflows found") if workflow_paths.empty?

workflow_paths.each do |path|
  document = load_yaml(path)
  relative = path.delete_prefix("#{Dir.pwd}/")
  fail_check("#{relative}: top-level permissions must be exactly contents: read") unless document["permissions"] == READ_ONLY

  expected = File.basename(path) == "release-cli.yml" ? RELEASE_JOB_PERMISSIONS : {}
  jobs = document.fetch("jobs", {})
  jobs.each do |job_name, job|
    actual = job["permissions"]
    wanted = expected[job_name]
    fail_check("#{relative}: job #{job_name} has unexpected permissions #{actual.inspect}") unless actual == wanted
    next unless wanted

    fail_check("#{relative}: privileged job #{job_name} must use the release environment") unless job["environment"] == "release"
  end
  missing = expected.keys - jobs.keys
  fail_check("#{relative}: missing permission-reviewed jobs: #{missing.join(', ')}") unless missing.empty?
end

(workflow_paths + [ACTION_FILE]).each do |path|
  relative = path.delete_prefix("#{Dir.pwd}/")
  each_uses(load_yaml(path), relative) do |reference, location|
    fail_check("#{location}: uses must be a string") unless reference.is_a?(String)
    next if reference.start_with?("./", "docker://")
    next if reference.match?(/@[0-9a-f]{40}\z/)

    fail_check("#{location}: external action is not pinned to a full commit SHA: #{reference}")
  end
end

puts "workflow security checks passed"
