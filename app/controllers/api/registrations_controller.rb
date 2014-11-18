module Api
  class RegistrationsController < ActionController::Base
    before_filter :authenticate

    respond_to :json

    def register
      required  = ['name', 'hostname', 'mac_address']
      validated = validate_params(params, required)
      respond_success
      Computer.create validated
    end

    # Standard success response 200
    def respond_success
      body = { :result  => true, :message => 'Success!' }
      render :json => body.to_json, :status => 200
    end

    def decommission
      required  = ['name', 'hostname', 'mac_address']
      validated = validate_params(params, required)
      @computer = Computer.where(
        :name        => validated['name']).where(
        :hostname    => validated['hostname']).where(
        :mac_address => validated['mac_address']).first
      respond_success
      @computer.destroy if @computer
    end

    # Ensure only valid params are accepted and that required params
    # are present
    def validate_params(params, required)
      defaults = {
        'computer_group_id' => ComputerGroup.find_by_name('Default').id,
        'unit_id'           => Unit.find_by_name('Default').id,
        'environment_id'    => Environment.find_by_name('production').id,
      }

      filtered = params.select { |k,v| required.include?(k) }
      unless filtered.keys.sort == required.sort
        raise ActiveModel::MissingAttributeError.new "You did not specify a required parameter: #{filtered}"
      end
      filtered.merge defaults
    end

    private

    def authenticate
      config_file = "#{Rails.root.to_s}/config/api.yaml"
      config      = YAML.load_file(config_file) if File.exists? config_file || nil
      if config.nil?
        respond_with(nil, :status => 401, :location => nil)
        return false
      end
      authenticate_or_request_with_http_basic do |user, password|
        user == config['user'] && password == config['password']
      end
    end

  end
end
