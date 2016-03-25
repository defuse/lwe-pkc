
require 'rubystats'

# XXX: Use a CSPRNG for the samplers

class UniformSampler
  def initialize(prime)
    @prime = prime
  end

  def sample()
    return FieldQElement.new(Random.rand(@prime))
  end
end

class PsiAlphaSampler
  def initialize(prime)
    @prime = prime
  end

  def sample()
    # "The distribution on Zq obtained by sampling a normal variable with mean
    # 0 and standard deviation alpha q / sqrt(2 pi), rounding the result to the
    # nearest integer and reducing it modulo q."

    # XXX: Who knows how secure this gem is (probably not at all...)
    gen = Rubystats::NormalDistribution.new(0, LWECore::PARAM_ALPHA * LWECore::PARAM_Q.to_f / Math.sqrt(2 * Math::PI))
    # XXX: Should there be an abs be there or are negative values done correctly?
    return FieldQElement.new(gen.rng().round().to_i % @prime)
  end
end

class NegToPosRSampler
  def initialize(prime)
    @prime = prime
  end

  def sample()
    return FieldQElement.new(Random.rand((-LWECore::PARAM_R)..LWECore::PARAM_R) % @prime)
  end
end
