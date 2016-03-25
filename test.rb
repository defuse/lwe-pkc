#!/usr/bin/env ruby

require_relative 'StupidECC'
require_relative 'LWE'


# Generate a keypair.
privkey = LWEPrivateKey.new
pubkey = privkey.publicKey

# XXX: This and the StupidECC stuff assumes values for PARAM_R and PARAM_L.

encodedMessage = StupidECC.encodeFourteenBytes("0123456789ABCD")
puts "Upon encryption:"
encodedMessageStr = encodedMessage.to_a.flatten.join('')
puts encodedMessageStr

ciphertext = pubkey.encryptMessage(encodedMessage)
plaintext = privkey.decryptCiphertext(ciphertext)

puts "Upon decryption:"
plaintextStr = plaintext.to_a.flatten.join('')
puts plaintextStr

decoded = StupidECC.decodeFourteenBytes(plaintext)

puts "Decoded: [#{decoded}]"

if decoded == "0123456789ABCD"
  puts "IT WORKS!"
else
  puts "IT DOES NOT WORK :("
end
