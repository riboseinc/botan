require_relative 'libbotan2'

module Botan2
  class RNG
    attr_reader :ptr
    def initialize(rng_type='system')
      rng_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan2.botan_rng_init(rng_ptr, rng_type)
      raise if rc != 0
      @ptr = rng_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan2.botan_rng_destroy(ptr)
    end

    def reseed(bits=256)
      rc = LibBotan2.botan_rng_reseed(@ptr, bits)
      raise if rc != 0
    end

    def get(length)
      out_buf = FFI::MemoryPointer.new(:uint8, length)
      rc = LibBotan2.botan_rng_get(@ptr, out_buf, length)
      raise if rc != 0
      out_buf.read_bytes(length)
    end
  end

  class MAC
    def initialize(algo)
      flags = 0
      mac_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan2.botan_mac_init(mac_ptr, algo, flags)
      raise if rc != 0
      @ptr = mac_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan2.botan_mac_destroy(ptr)
    end

    def clear
      rc = LibBotan2.botan_mac_clear(@ptr)
      raise if rc != 0
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_mac_output_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def set_key(key)
      rc = LibBotan2.botan_mac_set_key(@ptr, key, key.bytesize)
      raise if rc != 0
    end

    def update(x)
      rc = LibBotan2.botan_mac_update(@ptr, x, x.bytesize)
      raise if rc != 0
    end

    def final
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      rc = LibBotan2.botan_mac_final(@ptr, out_buf)
      raise if rc != 0
      out_buf.read_bytes(out_buf.size)
    end
  end

  class Hash
    def initialize(algo)
      flags = 0
      hash_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan2.botan_hash_init(hash_ptr, algo, flags)
      raise if rc != 0
      @ptr = hash_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan2.botan_hash_destroy(ptr)
    end

    def clear
      rc = LibBotan2.botan_hash_clear(@ptr)
      raise if rc != 0
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_hash_output_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def update(x)
      rc = LibBotan2.botan_hash_update(@ptr, x, x.bytesize)
      raise if rc != 0
    end

    def final
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      rc = LibBotan2.botan_hash_final(@ptr, out_buf)
      raise if rc != 0
      out_buf.read_bytes(out_buf.size)
    end
  end

  class Cipher
    def initialize(algo, encrypt=true)
      flags = encrypt ? 0 : 1
      cipher_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan2.botan_cipher_init(cipher_ptr, algo, flags)
      raise if rc != 0
      @ptr = cipher_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan2.botan_cipher_destroy(ptr)
    end

    def default_nonce_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_cipher_get_default_nonce_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def update_granularity
      gran_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_cipher_get_update_granularity(@ptr, gran_ptr)
      raise if rc != 0
      gran_ptr.read(:size_t)
    end

    def key_length
      kmin_ptr = FFI::MemoryPointer.new(:size_t)
      kmax_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_cipher_query_keylen(@ptr, kmin_ptr, kmax_ptr)
      raise if rc != 0
      return [kmin_ptr.read(:size_t), kmax_ptr.read(:size_t)]
    end

    def tag_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_cipher_get_tag_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def authenticated?
      tag_length > 0
    end

    def valid_nonce_length?(nonce_len)
      rc = LibBotan2.botan_cipher_valid_nonce_length(@ptr, nonce_len)
      raise if rc < 0
      return (rc == 1) ? true : false
    end

    def clear
      rc = LibBotan2.botan_cipher_clear(@ptr)
      raise if rc != 0
    end

    def set_key(key)
      key_buf = FFI::MemoryPointer.new(:uint8, key.bytesize)
      key_buf.write_bytes(key)
      rc = LibBotan2.botan_cipher_set_key(@ptr, key_buf, key_buf.size)
      raise if rc != 0
    end

    def set_assoc_data(ad)
      ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
      ad_buf.write_bytes(ad)
      rc = LibBotan2.botan_cipher_set_associated_data(@ptr, ad_buf, ad.size)
      raise if rc != 0
    end

    def start(nonce)
      nonce_buf = FFI::MemoryPointer.new(:uint8, nonce.bytesize)
      rc = LibBotan2.botan_cipher_start(@ptr, nonce_buf, nonce_buf.size)
      raise if rc != 0
    end

    def _update(txt, final)
      inp = txt ? txt : ''
      flags = final ? 1 : 0
      out_buf = FFI::MemoryPointer.new(:uint8, inp.bytesize + (final ? tag_length() : 0))
      out_written_ptr = FFI::MemoryPointer.new(:size_t)
      input_buf = FFI::MemoryPointer.new(:uint8, inp.bytesize)
      input_buf.write_bytes(inp)
      inp_consumed_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan2.botan_cipher_update(@ptr, flags, out_buf, out_buf.size,
                                         out_written_ptr, input_buf, input_buf.size,
                                         inp_consumed_ptr)
      raise if inp_consumed_ptr.read(:size_t) != inp.bytesize
      out_buf.read_bytes(out_written_ptr.read(:size_t))
    end

    def update(txt)
      _update(txt, false)
    end

    def finish(txt=nil)
      _update(txt, true)
    end
  end

  def self.kdf(algo, secret, out_len, salt, label)
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)

    secret_buf = FFI::MemoryPointer.new(:uint8, secret.bytesize)
    secret_buf.write_bytes(secret)

    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)

    label_buf = FFI::MemoryPointer.from_string(label)
    label_buf = FFI::MemoryPointer.new(:uint8, label.bytesize)
    label_buf.write_bytes(label)
    rc = LibBotan2.botan_kdf(algo, out_buf, out_buf.size, secret_buf, secret_buf.size, salt_buf, salt_buf.size, label_buf, label_buf.size)
    raise if rc != 0
    out_buf.read_bytes(out_len)
  end

  def self.pbkdf(algo, password, out_len, iterations=10000, salt=RNG.new.get(12))
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)
    rc = LibBotan2.botan_pbkdf(algo, out_buf, out_len, password, salt_buf, salt_buf.size, iterations)
    raise if rc != 0
    return [salt, iterations, out_buf.read_bytes(out_len)]
  end

  def self.pbkdf_timed(algo, password, out_len, ms_to_run=300, salt=RNG.new.get(12))
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)
    iterations_ptr = FFI::MemoryPointer.new(:size_t)
    rc = LibBotan2.botan_pbkdf_timed(algo, out_buf, out_len, password, salt_buf, salt_buf.size, ms_to_run, iterations_ptr)
    raise if rc != 0
    return [salt, iterations_ptr.read(:size_t), out_buf.read_bytes(out_len)]
  end

  def self.bcrypt(passwd, rng, work_factor=10)
    out_len = 64
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    flags = 0
    out_len_ptr = FFI::MemoryPointer.new(:size_t)
    out_len_ptr.write(:size_t, out_len)
    rc = LibBotan2.botan_bcrypt_generate(out_buf, out_len_ptr, passwd, rng.ptr, work_factor, flags)
    raise if rc != 0
    result = out_buf.read_bytes(out_len_ptr.read(:size_t))
    result = result[0..-2] if result[-1] == "\x00"
    result
  end

  def self.check_bcrypt(passwd, bcrypt)
    rc = LibBotan2.botan_bcrypt_is_valid(passwd, bcrypt)
    return rc == 0
  end
end # module

