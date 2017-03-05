class User < ApplicationRecord

	attr_accessor :remember_token, :activation_token, :reset_token

	before_save :downcase_email
	before_create :create_activation_digest
	validates :name, presence: true, length: { maximum: 50 }
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
	validates :email, presence: true, length: { maximum: 255 },
		format: { with: VALID_EMAIL_REGEX },
		uniqueness: { case_sensitive: false }
	has_secure_password
	validates :password, presence: true, length: { minimum: 6 }, allow_nil: true

	def remember
	    self.remember_token = User.new_token
	    update_attribute(:remember_digest, User.digest(remember_token))
	end

	def User.digest(string)#self是User类
    	cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
   		BCrypt::Password.create(string, cost: cost)
 	end

 	def User.new_token#self是User类
 		SecureRandom.urlsafe_base64
 	end

 	def authenticated?(attribute, token)
 		digest = send("#{attribute}_digest")
	    return false if digest.nil?
	    BCrypt::Password.new(digest).is_password?(token)
	end
	

 	def forget
 		update_attribute(:remember_digest, nil)
 	end

 	def activate
 		# self.update_attribute(:activated, true)
 		# self.update_attribute(:activated_at, Time.zone.now)
 		self.update_columns(activated: true, activated_at: Time.zone.now)
 	end

 	def send_activation_email
 		UserMailer.account_activation(self).deliver_now
 	end

    def create_reset_digest
 		self.reset_token = User.new_token
 		update_attribute(:reset_digest, User.digest(reset_token))
 		update_attribute(:reset_sent_at, Time.zone.now)
 		# self.update_columns(reset_digest: true, reset_sent_at: Time.zone.now)
 	end

 	def send_password_reset_email
 		UserMailer.password_reset(self).deliver_now
 	end

 	def password_reset_expired?
 		reset_sent_at < 2.hours.ago
 	end


 	private
 		def create_activation_digest
 			self.activation_token = User.new_token
 			self.activation_digest = User.digest(activation_token)
 		end

 		def downcase_email
 			self.email = email.downcase
 		end


end