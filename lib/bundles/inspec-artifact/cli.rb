# encoding: utf-8
# author: Dave Parfitt
#
require 'base64'
require 'openssl'
require 'pathname'

module Artifact
  class CLI < Inspec::BaseCLI
    namespace 'artifact'

    # TODO: find another solution, once https://github.com/erikhuda/thor/issues/261 is fixed
    def self.banner(command, _namespace = nil, _subcommand = false)
      "#{basename} #{subcommand_prefix} #{command.usage}"
    end

    def self.subcommand_prefix
      namespace
    end

    desc "generate NAME", "TODO"
    option :keyname, type: :string, required: true,
      desc: 'Desriptive name of key'
    option :keydir, type: :string, default: "./",
        desc: 'Directory to search for keys'
    def generate_keys
        puts "Generating keys"
        keygen
    end

    desc "sign", "TODO"
    option :infile, type: :string, required: true,
      desc: 'File to sign'
    option :outfile, type: :string, required: true,
      desc: 'Signed artifact'
    option :keyname, type: :string, required: true,
      desc: 'Desriptive name of key'
    #option :keydir, type: :string, default: "./",
    #    desc: 'Directory to search for keys'
    def sign_file
        puts "Signing file"
        sign
    end

    desc "verify", "TODO"
    option :infile, type: :string, required: true,
      desc: 'File to sign'
    option :outfile, type: :string, required: true,
      desc: 'Verified artifact'
    option :keyname, type: :string, required: true,
      desc: 'Desriptive name of key'
    def verify_file
        puts "Verifying file"
        verify
    end

    private
    def keygen
        key = OpenSSL::PKey::RSA.new 2048
        puts "Generating private key"
        open "#{options["keyname"]}.pem.key", 'w' do |io| io.write key.to_pem end
        puts "Generating public key"
        open "#{options["keyname"]}.pem.pub", 'w' do |io| io.write key.public_key.to_pem end
    end

    def sign
        #sed '/^$/q' test.txt
        #sed '1,/^$/d' test.txt
        # bundle exec inspec artifact generate --keyname dparfitt
        # bundle exec inspec artifact sign --infile fake_profile.tar.gz --outfile signed.iaf --keyname dparfitt
        # bundle exec inspec artifact verify --infile signed.iaf --outfile bar.tar.gz --keyname dparfitt

        puts "Signing #{options["infile"]} with key #{options["keyname"]}"
        signing_key = OpenSSL::PKey::RSA.new File.read "#{options["keyname"]}.pem.key"
        # TODO: error handling around invalid files etc
        content = IO.binread(options["infile"])
        sha = OpenSSL::Digest::SHA512.new
        signature = signing_key.sign sha, content
        signature_base64 = Base64.encode64(signature)
        puts "SIGNATURE = \n#{signature_base64}"
        tar_content = IO.binread(options["infile"])
        open(options["outfile"], 'wb') do |f|
            f.puts("INSPEC-1")
            f.puts(options["keyname"])
            f.puts("SHA512")
            f.puts(signature_base64)
            f.puts("")
            f.write(tar_content)
        end
    end


    def verify
        puts "Verifying #{options["outfile"]} with key #{options["keyname"]}"
        verification_key = OpenSSL::PKey::RSA.new File.read "#{options["keyname"]}.pem.pub"

        f = File.open(options["infile"], "r")
        file_version = f.readline()
        file_keyname = f.readline()
        file_alg = f.readline()

        file_sig = ""
        while (line = f.readline) != "\n"
            file_sig += line
        end

        f.readline()
        bytes = f.readline()
        puts "version = #{file_version}"
        puts "keyname = #{file_keyname}"
        puts "alg     = #{file_alg}"
        puts "sig     = #{file_sig}"
        f.close()

        f = File.open(options["infile"], "r")
        while f.readline() != "\n" do
            #puts "Skipping line"
        end
        content = f.read()

        signature = Base64.decode64(file_sig)
        digest = OpenSSL::Digest::SHA512.new
        if verification_key.verify digest, signature, content
            puts 'Signature valid'
            File.write(options["outfile"], content)
        else
            puts 'Invalid'
        end

    end
  end

  # register the subcommand to Inspec CLI registry
  Inspec::Plugins::CLI.add_subcommand(Artifact::CLI, 'artifact', 'artifact TEMPLATE ...', 'Does stuff', {})
end
