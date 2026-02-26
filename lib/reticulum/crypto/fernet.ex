defmodule Reticulum.Crypto.Fernet do
  @moduledoc """
  Reticulum token cipher (Fernet-derived, without version/timestamp fields).

  Reticulum uses a compact token format compared to canonical Fernet:

  - canonical Fernet: `version || timestamp || iv || ciphertext || hmac`
  - Reticulum token: `iv || ciphertext || hmac`

  Token key material layout follows the reference implementation:

  - 32-byte total key: `signing_key(16) || encryption_key(16)` -> AES-128-CBC
  - 64-byte total key: `signing_key(32) || encryption_key(32)` -> AES-256-CBC

  References:

  - Fernet spec: https://github.com/fernet/spec/blob/master/Spec.md
  - Python reference token implementation: `Reticulum/RNS/Cryptography/Token.py`
  """
  alias Reticulum.Crypto

  @typedoc "Token cipher context"
  @type t :: %__MODULE__{
          sig_key: binary(),
          enc_key: binary(),
          cipher: :aes_128_cbc | :aes_256_cbc
        }

  defstruct [:sig_key, :enc_key, :cipher]

  @doc "Builds a token context from 32-byte or 64-byte key material."
  def new(key)

  def new(<<sig_key::binary-size(16), enc_key::binary-size(16)>>) do
    %__MODULE__{sig_key: sig_key, enc_key: enc_key, cipher: :aes_128_cbc}
  end

  def new(<<sig_key::binary-size(32), enc_key::binary-size(32)>>) do
    %__MODULE__{sig_key: sig_key, enc_key: enc_key, cipher: :aes_256_cbc}
  end

  @doc "Verifies token HMAC in constant time."
  def sig_valid?(%__MODULE__{sig_key: sig_key}, token)
      when is_binary(token) and byte_size(token) > 32 do
    signed_size = byte_size(token) - 32
    <<signed::binary-size(signed_size), received_sig::binary-size(32)>> = token
    expected_sig = Crypto.hmac(sig_key, signed)

    :crypto.hash_equals(received_sig, expected_sig)
  end

  def sig_valid?(_context, _token), do: false

  @doc "Encrypts plaintext into `iv || ciphertext || hmac` token format."
  def encrypt(%__MODULE__{enc_key: enc_key, sig_key: sig_key, cipher: cipher}, plain_text)
      when is_binary(plain_text) do
    # random IV
    iv = :crypto.strong_rand_bytes(16)

    # AES encrypt
    cipher_text =
      :crypto.crypto_one_time(cipher, enc_key, iv, plain_text,
        encrypt: true,
        padding: :pkcs_padding
      )

    # calculate signature
    signature = Crypto.hmac(sig_key, iv <> cipher_text)

    # construct final token
    iv <> cipher_text <> signature
  end

  @doc "Decrypts token after HMAC validation. Returns `{:ok, plaintext}` or `{:error, :invalid_signature}`."
  def decrypt(%__MODULE__{enc_key: key, cipher: cipher} = context, token) when is_binary(token) do
    if sig_valid?(context, token) do
      signed_size = byte_size(token) - 32
      <<signed::binary-size(signed_size), _signature::binary-size(32)>> = token
      <<iv::binary-size(16), cipher_text::binary>> = signed

      {:ok,
       :crypto.crypto_one_time(cipher, key, iv, cipher_text,
         encrypt: false,
         padding: :pkcs_padding
       )}
    else
      {:error, :invalid_signature}
    end
  end
end
