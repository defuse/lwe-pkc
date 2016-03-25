# The stupidest possible way to (sometimes, maybe) correct arbitrary 0-, 1-, or
# 2-bit errors on 14-byte messages. Because I'm too lazy to figure out how
# an actual error correcting code works.

require 'digest'

class StupidECC
  def self.encodeFourteenBytes(msg)

    if msg.bytesize != 14
      raise ArgumentError.new("Must be 14 bytes.")
    end

    # Convert to an array of bits 112 bits.
    bits = msg.unpack("B*")[0].split('').map { |b| b.to_i }

    # Append 24 bits of SHA256 to detect errors (and correct by brute-force).
    hash_bits = Digest::SHA256.digest(msg).slice(0, 3).unpack("B*")[0].split('').map { |b| b.to_i }
    bits = bits + hash_bits

    if bits.length != LWECore::PARAM_L
      raise "BAD!"
    end

    encoded = Matrix::build(LWECore::PARAM_L, 1) do |row, col|
      FieldQElement.new(bits[row])
    end

    return encoded
  end

  def self.decodeFourteenBytes(encoded)

    0.upto(LWECore::PARAM_L - 1) do |i|
      encoded[i, 0] = encoded[i, 0].to_i
    end

    0.upto(LWECore::PARAM_L) do |err_pos_a|
      0.upto(LWECore::PARAM_L) do |err_pos_b|

        test = encoded.clone()

        [err_pos_a, err_pos_b].each do |err_pos|
          if err_pos < LWECore::PARAM_L
            # XXX: implement XOR or something in FieldQElement so we don't have
            # to do this...
            if test[err_pos, 0] == 0
              test[err_pos, 0] = 1
            else
              test[err_pos, 0] = 0
            end
          end
        end

        if self.checkForErrors(test)
          return self.getMessagePart(test)
        end
      end
    end
    raise "Couldn't decode."
  end

  def self.checkForErrors(encoded)
    msg = self.getMessagePart(encoded)
    sha = self.getSHA256Part(encoded)
    Digest::SHA256.digest(msg).slice(0, 3) == sha
  end

  def self.getMessagePart(encoded)
    [encoded.to_a.flatten.join('').slice(0, 112)].pack("B*")
  end

  def self.getSHA256Part(encoded)
    [encoded.to_a.flatten.join('').slice(112, 24)].pack("B*")
  end
end
