# encoding: utf-8
# author: Dave Parfitt
#
require 'base64'
require 'openssl'
require 'pathname'

# Demo:
# 0) Generate a pair of keys to use to sign and verify an artifact:
#       bundle exec inspec artifact generate --keyname foo
# 1) Sign a tar file (this would be a Inspec profile, but I use a .tar.gz to demo)
#       bundle exec inspec artifact sign --infile fake_profile.tar.gz --outfile signed.iaf --keyname foo
# 2) The public key can be distributed with signed artifacts.
#       bundle exec inspec artifact verify --infile signed.iaf --outfile bar.tar.gz

# Notes:
# Installing artifacts
#   The current implementation allows for a .iaf file to be extracted to a .tar.gz
#   file with verification. We could extend the command to install a profile
#   to a given location w/ verification. (via lib/inspec/file_provider.rb)
#
# Generate keys
#   The initial implementation uses 2048 bit RSA key pairs (public + private).
#   Public keys must be available for a customer to install and verify an artifact.
#   Private keys should be stored in a secure location and NOT be distributed.
#     (They're only for creating artifacts).
#
#
# .IAF file format
#   .iaf = "Inspec Artifact File", easy to rename if you'd like something more appropriate.
#   The iaf file wraps a binary artifact with some metadata. The first implementation
#   looks like this:
#
# INSPEC-1
# name_of_signing_key
# algorithm
# signature
# <empty line>
# binary-blob
# <eof>
#
# Let's look at each line:
# INSPEC-1:
#   This is the artifact version descriptor. It should't change unless the
#   format of the archive changes.
#
# name_of_signing_key
#   The name of the public key that can be used to verify an artifact
#
# algorithm
#   The digest used to sign, I picked SHA512 to start with.
#   If we support multiple digests, we'll need to have the verify() method
#   support each digest.
#
# signature
#   The result of passing the binary artifact through the digest algorithm above.
#   Result is base64 encoded.
#
# <empty line>
#   We use an empty line to separate artifact header from artifact body (binary blob).
#   The artifact body can be anything you like.
#
# binary-blob
#   A binary blob, most likely a .tar.gz or tar.xz file. We'll need to pick one and
#   stick with it as part of the "INSPEC-1" artifact version. If we change block
#   format, the artifact version descriptor must be incremented, and the sign()
#   and verify() methods must be updated to support a newer version.
#
#
# Key revocation
#   This implementation doesn't support key revocation. However, a customer
#   can remove the public cert file before installation, and artifacts will then
#   fail verification.
#
# Key locations
#   This implementation uses the current working directory to find public and
#   private keys. We should establish a common key directory (similar to /hab/cache/keys
#   or ~/.hab/cache/keys in Habitat).
#
# Extracting artifacts outside of Inspec
#   As in Habitat, the artifact format for Inspec allows the use of common
#   Unix tools to read the header and body of an artifact.
# To extract the header from a .iaf:
#        sed '/^$/q' foo.iaf
# To extract the raw content from a .iaf:
#        sed '1,/^$/d' foo.iaf


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
        puts "Signing #{options["infile"]} with key #{options["keyname"]}"
        signing_key = OpenSSL::PKey::RSA.new File.read "#{options["keyname"]}.pem.key"
        # TODO: error handling around invalid files etc
        content = IO.binread(options["infile"])
        # TODO: do we allow different digests? If so, the verify method
        #       will have to be able to handle each
        sha = OpenSSL::Digest::SHA512.new
        signature = signing_key.sign sha, content
        # convert the signature to Base64
        signature_base64 = Base64.encode64(signature)
        puts "SIGNATURE = \n#{signature_base64}"
        tar_content = IO.binread(options["infile"])
        open(options["outfile"], 'wb') do |f|
            f.puts("INSPEC-1") # TODO: constant
            f.puts(options["keyname"])
            f.puts("SHA512") # TODO
            f.puts(signature_base64)
            f.puts("") # newline separates artifact header with body
            f.write(tar_content)
        end
    end


    def verify
        puts "Verifying #{options["outfile"]}"

        f = File.open(options["infile"], "r")
        file_version = f.readline()
        file_keyname = f.readline()
        file_alg = f.readline()

        # TODO: ensure file_version is correct
        # TODO: ensure file_alg is correct
        # TODO: ensure file_keyname exists
        file_sig = ""
        # the signature is multi-line
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

        # TODO: ensure we have the key
        # TODO: look in a common key location first, allow alternate locations
        #       to be specified
        verification_key = OpenSSL::PKey::RSA.new File.read "#{file_keyname}.pem.pub"

        f = File.open(options["infile"], "r")
        while f.readline() != "\n" do
            # nop
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
