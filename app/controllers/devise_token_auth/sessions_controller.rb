# frozen_string_literal: true

# see http://www.emilsoman.com/blog/2013/05/18/building-a-tested/
module DeviseTokenAuth
  class SessionsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, only: [:destroy]
    after_action :reset_session, only: [:destroy]

    def new
      render_new_error
    end

    def create
      # Check

      # | /sign_in | POST | Email authentication. Requires **`email`** and **`password`** as params.
      # This route will return a JSON representation of the `User` model on successful login 
      # along with the `access-token` and `client` in the header of the response. |


      # 일단 params안에 정보 중 email, password가 valid한지 확인하고 
      # 1.valid하지 않으면 예전처럼 
      # 2.valid하면 기기정보가 valid한지 확인하고
        # 2-1.valid하면 뒤의 프로세스 다 진행
        # 2-2.valid하지 않으면 인증요청 - 이 요청을 어디서 받는지는 알아봐야 한다 (redux-auth)
      field = (resource_params.keys.map(&:to_sym) & resource_class.authentication_keys).first
      # to_sym converts a string to a symbol. For example, "a".to_sym becomes :a.

      @resource = nil
      if field
        q_value = get_case_insensitive_field_from_resource_params(field)

        @resource = find_resource(field, q_value)
        # @resource는 devise가 가지는 여러 속성(method, class 등) 중 field와 q_value에 일치하는 것...?
      end

      if @resource && valid_params?(field, q_value) && (!@resource.respond_to?(:active_for_authentication?) || @resource.active_for_authentication?)
        # 이런식으로 .~~~? 문법은 그냥 그대로 해석하면 될 듯하다 Ex> .all?
        # 일단 제대로 들어왔는지만 확인(이게 비밀번호가 맞는지까지는 x ????)
        # 확인할 수 있는 상태인가
        valid_password = @resource.valid_password?(resource_params[:password])
        # 여기서 valid_password? 이런건 devise의 함수를 사용하는 것 같은데 그 중에서 어떤건지 어떻게 알아내야 할까요?
             
        # Verifies whether a password (ie from sign in) is the user password.
        # def valid_password?(password)
        #    Devise::Encryptor.compare(self.class, encrypted_password, password)
        # end
        # 이 친구로 추정됨 XXX
        # Model.valid_password가 이거고
        # @resource가 해당 정보와 일치하는 유저?로 보인다

        # Note: unlike `Model.valid_password?`, this method does not actually
        # ensure that the password in the params matches the password stored in
        # the database. It only checks if the password is *present*. Do not rely
        # on this method for validating that a given password is correct.
        #  def valid_password?
        #    password.present?
        #  end
        # 이 친구로 추정된다

        if (@resource.respond_to?(:valid_for_authentication?) && !@resource.valid_for_authentication? { valid_password }) || !valid_password
          return render_create_error_bad_credentials
          # 이게 invalid login credentials -> 잘못된 정보
        end

        # 여기에서 cookie 값을 확인한다
        #number = params[:number]
        #if (!Device.find_by_number(number=number))
        #  return render_request_for_device
        #  # 만들고 있는 response
        #end
 
        @client_id, @token = @resource.create_token
        @resource.save

        sign_in(:user, @resource, store: false, bypass: false)

        yield @resource if 
        # @resource가 블록이면 do end 했을 때 하나씩 뽑을 수 있다?

        render_create_success
      elsif @resource && !(!@resource.respond_to?(:active_for_authentication?) || @resource.active_for_authentication?)
        if @resource.respond_to?(:locked_at) && @resource.locked_at
          render_create_error_account_locked
          # "Your account has been locked due to an excessive number of unsuccessful sign in attempts."
          # 계속 틀려서 잠긴 경우
        else
          render_create_error_not_confirmed
          # "A confirmation email was sent to your account at '%{email}'. You must follow the instructions in the email before your account can be activated"
        end
      else
        render_create_error_bad_credentials
        # "Invalid login credentials. Please try again."
      end
    end

    def destroy
      # remove auth instance variables so that after_action does not run
      user = remove_instance_variable(:@resource) if @resource
      client_id = remove_instance_variable(:@client_id) if @client_id
      remove_instance_variable(:@token) if @token

      if user && client_id && user.tokens[client_id]
        user.tokens.delete(client_id)
        user.save!

        yield user if block_given?
        # 되나?
        render_destroy_success
      else
        render_destroy_error
      end
    end

    protected

    def valid_params?(key, val)
      resource_params[:password] && key && val
    end

    def get_auth_params
      auth_key = nil
      auth_val = nil

      # iterate thru allowed auth keys, use first found
      resource_class.authentication_keys.each do |k|
        if resource_params[k]
          auth_val = resource_params[k]
          auth_key = k
          break
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(auth_key)
        auth_val.downcase!
      end

      { key: auth_key, val: auth_val }
    end

    def render_new_error
      render_error(405, I18n.t('devise_token_auth.sessions.not_supported'))
    end

    def render_create_success
      render json: {
        data: resource_data(resource_json: @resource.token_validation_response)
        # module DeviseTokenAuth를 했기 때문에 거기에 있는 token_validation_response 사용가능 -> import가 아니고 module을 만드는 것 같은데..?
        # created_at, updated_at을 제외하고 json 형태로 바꿔주는 것 같다
      }
    end

    # 기기인증을 요청
    def render_request_for_device
      render json: {
        data: resource_data(resource_json: @resource.token_validation_response)
      }
    end

    def render_create_error_not_confirmed
      render_error(401, I18n.t('devise_token_auth.sessions.not_confirmed', email: @resource.email))
    end

    def render_create_error_account_locked
      render_error(401, I18n.t('devise.mailer.unlock_instructions.account_lock_msg'))
    end

    def render_create_error_bad_credentials
      render_error(401, I18n.t('devise_token_auth.sessions.bad_credentials'))
      # I18n은 국제화를 의미한다.

      # def render_error(status, message, data = nil)
      #   response = {
      #     success: false,
      #     errors: [message]
      #   }
      #   response = response.merge(data) if data
      #   render json: response, status: status
      # end
      # 이렇게 에러가 나면 success를 false로 해주고 message를 보내준다
    end

    def render_destroy_success
      render json: {
        success:true
      }, status: 200
    end

    def render_destroy_error
      render_error(404, I18n.t('devise_token_auth.sessions.user_not_found'))
    end

    private

    def resource_params
      params.permit(:email, :password, :number)

      # 여기가 resource_params에 sign_in 정보를 저장하는 함수인 것 같다. / email, password + overrides에서는 number까지 되어있는 상태
    end
  end
end
