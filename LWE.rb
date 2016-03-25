# **TOY** **INSECURE** LWE Public Key Crypto
# Copyright (C) Taylor Hornby 2016
#
# This is a toy implementation of the LWE cryptosystem presented in Algorithm
# 5.2 in Post-Quantum Cryptography. IT IS NOT SECURE BY ANY MEASURE SO DO NOT
# FUCKING USE IT FOR ANYTHING.
#
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.
# Repeat after me: THIS CODE IS INSECURE AND I WILL NOT USE IT FOR ANYTHING.

require 'matrix'
require_relative 'Samplers'

# XXX: HACK: Fix all the other code so that we don't need to do this.
# XXX: StupidECC also depends on us doing this.
class Matrix
  def []=(i, j, x)
    @rows[i][j] = x
  end
end

class FieldQElement
  attr_accessor :value

  def initialize(value = 0)
    @value = value % LWECore::PARAM_Q
  end

  def +(other)
    if other.is_a? self.class
      value = (@value + other.value) % LWECore::PARAM_Q
    else
      value = (@value + other) % LWECore::PARAM_Q
    end
    FieldQElement.new( value )
  end

  def *(other)
    if other.is_a? self.class
      value = (@value * other.value) % LWECore::PARAM_Q
    else
      value = (@value * other) % LWECore::PARAM_Q
    end
    FieldQElement.new( value )
  end

  def -(other)
    if other.is_a? self.class
      value = (@value - other.value) % LWECore::PARAM_Q
    else
      value = (@value - other) % LWECore::PARAM_Q
    end
    FieldQElement.new( value )
  end

  def coerce(other)
    [self.class.new(other), self]
  end

  def to_s
    @value.to_s
  end

  def inspect
    @value.inspect
  end

  def to_i
    @value
  end
end

class LWEPrivateKey

  attr_accessor :publicKey

  def initialize
    puts "Generating the private key..."
    uniform = UniformSampler.new(LWECore::PARAM_Q)
    @matrixS = LWECore::sampleRandomMatrix(LWECore::PARAM_N, LWECore::PARAM_L, uniform)
    puts "Done generating the private key."

    @publicKey = LWEPublicKey.new(@matrixS)
  end

  def decryptCiphertext(ciphertext)
    postF = ciphertext.vectorC - @matrixS.transpose * ciphertext.vectorU

    qOverT = LWECore::PARAM_Q.to_f / LWECore::PARAM_T.to_f
    message = Matrix::build(LWECore::PARAM_L, 1) do |row, col|
      # XXX: Do this without using floating point
      # XXX: The mod here isn't supposed to be necessary... but I was getting
      # 2's in the output, WTF... I bet the computation of postF or some part of
      # it isn't actually done modulo PARAM_Q.
      FieldQElement.new( (postF[row, col].value.to_f / qOverT).round().to_i % LWECore::PARAM_T )
    end
    return message
  end

end

class LWEPublicKey
  def initialize(matrixS)
    puts "Generating the public key..."
    uniform = UniformSampler.new(LWECore::PARAM_Q)
    @matrixA = LWECore::sampleRandomMatrix(LWECore::PARAM_M, LWECore::PARAM_N, uniform)

    psialpha = PsiAlphaSampler.new(LWECore::PARAM_Q)
    matrixE = LWECore::sampleRandomMatrix(LWECore::PARAM_M, LWECore::PARAM_L, psialpha)

    @matrixP = @matrixA * matrixS + matrixE
    puts "Done generating the public key."
  end

  # XXX: Check 'message' is the right kind of thing we expect it to be.
  def encryptMessage(message)
    ciphertext = LWECiphertext.new

    negtoposr = NegToPosRSampler.new(LWECore::PARAM_Q)
    vectorA = LWECore::sampleRandomMatrix(LWECore::PARAM_M, 1, negtoposr)

    # Apply the function F
    qOverT = LWECore::PARAM_Q.to_f / LWECore::PARAM_T.to_f
    afterF = Matrix::build(LWECore::PARAM_L, 1) do |row, col|
      # XXX: do this without using floating point
      FieldQElement.new((message[row, col].value.to_f * qOverT).round().to_i)
    end

    ciphertext.vectorU = @matrixA.transpose * vectorA
    ciphertext.vectorC = @matrixP.transpose * vectorA + afterF

    return ciphertext
  end

end

class LWECiphertext
  attr_accessor :vectorU, :vectorC
end

class LWECore
  # These parameters were taken from Post-Quantum Cryptography (the Springer
  # book edited by DJB) from Table 3 in the Lattice-Based Cryptography chapter.
  # XXX: I HAVE NO IDEA HOW SECURE THESE PARAMETERS ARE IF AT ALL!
  PARAM_N = 136
  PARAM_M = 2008
  PARAM_L = 136
  PARAM_T = 2
  PARAM_R = 1
  PARAM_Q = 2003
  PARAM_ALPHA = 0.0065

  def self::sampleRandomMatrix(rows, cols, sampler)
    matrix = Matrix.zero(rows, cols)
    rows.times do |r|
      cols.times do |c|
        matrix[r, c] = sampler.sample()
      end
    end
    return matrix
  end
end
