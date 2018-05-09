# Be sure to restart your server when you modify this file.

# Expertiza Security loads the encryption secrets used by the Expertiza Security module.
secret_keys_file = File.join(Rails.root, 'config', 'secret_keys.yml')
secret_salts_file = File.join(Rails.root, 'config', 'secret_salts.yml')
SECRET_KEYS =  YAML.load(File.open(secret_keys_file))[Rails.env.to_sym]
SECRET_SALTS =  YAML.load(File.open(secret_salts_file))[Rails.env.to_sym]