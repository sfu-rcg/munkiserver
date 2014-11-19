module Api

  class RegistrationsControllerError < StandardError
  end

  class RegistrationsController < ActionController::Base

    before_filter :load_config
    before_filter :check_ip
    before_filter :authenticate
    before_filter :find_computer

    rescue_from Api::RegistrationsControllerError,
      with: :respond_internal_error
    rescue_from ActiveModel::MissingAttributeError,
      with: :respond_internal_error

    respond_to :json

    def register
      log "Registering: #{@validated}"
      msg, code = if @computer
        ["Pre-Existing Record: #{@computer}", 200]
      else
        Computer.create(@validated.merge(reg_defaults))
        ["Created: #{@computer}", 200]
      end
      respond_and_log msg, code
    end

    def decommission
      log "Decommissioning: #{@validated}"
      msg, code = if @computer
        @computer.destroy
        ["Destroyed: #{@computer}", 200]
      else
        ["Record not found: #{@validated}", 404]
      end
      respond_and_log msg, code
    end

    private

    def reg_defaults
      {
        'computer_group_id' => ComputerGroup.find_by_name('Default').id,
        'unit_id'           => Unit.find_by_name('Default').id,
        'environment_id'    => Environment.find_by_name('production').id,
      }
    end

    def find_computer
      required   = ['name', 'hostname', 'mac_address']
      @validated = validate_params(params, required)
      @computer  = Computer.where(
        :name        => @validated['name']).where(
        :hostname    => @validated['hostname']).where(
        :mac_address => @validated['mac_address']).first
    end

    # Ensure only valid params are accepted and that required params
    # are present
    def validate_params(params, required)
      filtered = params.select { |k,v| required.include?(k) }
      unless filtered.keys.sort == required.sort
        raise ActiveModel::MissingAttributeError.new "You did not specify a required parameter: #{filtered}"
      end
      filtered
    end

    # Send a message to the Rails log
    def log(msg)
      Rails.logger.info "[RegistrationsController] #{msg}"
    end

    # Render the results of a query as JSON
    def render_data_as_json(data, status=200)
      render :json => data.to_json, :status => status
    end

    # Generic HTTP response method with Rails logging
    def respond_and_log(msg, code=200, result=nil)
      log(msg)
      render_data_as_json({ :result => result, :message => msg }, code)
    end

    # Standard error response 500
    def respond_internal_error(err)
      respond_and_log(err.message, 500, false)
    end

    def check_ip
      unless @config['hosts_allow'].member? request.remote_ip
        respond_and_log "Unauthorized Client IP: #{client_ip}", 403
      end
    end

    def load_config
      config_file = "#{Rails.root.to_s}/config/api.yaml"
      @config     = YAML.load_file(config_file) if File.exists? config_file || nil
      if @config.nil?
        respond_internal_error "Cannot load API configuration file!"
      end
    end

    def authenticate
      authenticate_or_request_with_http_basic do |user, password|
        user == @config['user'] && password == @config['password']
      end
    end

  end
end
