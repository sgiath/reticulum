defmodule Reticulum.Identity do
  @moduledoc """
  Reticulum identity key material and cryptographic operations.

  Responsibilities:

  - hold encryption/signing keypairs
  - derive stable identity hash from public key material
  - perform identity encryption/decryption (X25519 + HKDF + token cipher)
  - sign and validate messages (Ed25519)

  Hash derivation matches the reference implementation by hashing
  `enc_pub <> sig_pub` and truncating to 16 bytes.

  References:

  - Python reference: `Reticulum/RNS/Identity.py`
  - X25519: RFC 7748
  - Ed25519: RFC 8032
  """

  alias Reticulum.Crypto
  alias Reticulum.Crypto.Fernet

  @derived_key_len 64

  @typedoc "Identity key material and derived hash"
  @type t :: %__MODULE__{
          enc_sec: binary() | nil,
          enc_pub: binary() | nil,
          sig_sec: binary() | nil,
          sig_pub: binary() | nil,
          hash: binary() | nil
        }

  defstruct [:enc_sec, :enc_pub, :sig_sec, :sig_pub, :hash]

  @doc "Creates a new identity; pass `gen_keys: false` for an empty shell."
  def new(opts \\ []) do
    gen_keys = Keyword.get(opts, :gen_keys, true)

    %__MODULE__{}
    |> maybe_gen_keys(gen_keys)
    |> update_hash()
  end

  defp maybe_gen_keys(%__MODULE__{} = identity, false), do: identity

  defp maybe_gen_keys(%__MODULE__{} = identity, true) do
    identity
    |> gen_enc_key()
    |> gen_sig_key()
  end

  @doc "Generates and stores X25519 key material on the identity."
  def gen_enc_key(%__MODULE__{} = identity) do
    {pub, sec} = Crypto.x25519()
    %__MODULE__{identity | enc_sec: sec, enc_pub: pub}
  end

  @doc "Generates and stores Ed25519 key material on the identity."
  def gen_sig_key(%__MODULE__{} = identity) do
    {pub, sec} = Crypto.ed25519()
    %__MODULE__{identity | sig_sec: sec, sig_pub: pub}
  end

  @doc "Updates identity hash when both public keys are present."
  def update_hash(%__MODULE__{enc_pub: enc_pub, sig_pub: sig_pub} = identity)
      when is_binary(enc_pub) and is_binary(sig_pub) do
    <<hash::binary-size(16), _rest::binary>> = Crypto.sha256(enc_pub <> sig_pub)
    %__MODULE__{identity | hash: hash}
  end

  def update_hash(%__MODULE__{} = identity), do: identity

  @doc "Encrypts plaintext for the identity public key and prepends ephemeral pubkey."
  def encrypt(identity, plain_text, opts \\ [])

  def encrypt(%__MODULE__{enc_pub: enc_pub, hash: hash}, plain_text, opts)
      when is_list(opts) do
    target_enc_pub = Keyword.get(opts, :target_enc_pub, enc_pub)
    {ephemeral_pub, ephemeral_sec} = Crypto.x25519()

    cipher_text =
      %{sec: ephemeral_sec, pub: target_enc_pub}
      |> Crypto.compute()
      |> Crypto.hkdf(hash, <<>>, @derived_key_len)
      |> Fernet.new()
      |> Fernet.encrypt(plain_text)

    ephemeral_pub <> cipher_text
  end

  @doc """
  Decrypts identity ciphertext.

  Returns:

  - `{:ok, plaintext}` on success
  - `{:error, :missing_private_key}` when no private key exists
  - `{:error, :invalid_ciphertext}` for malformed/invalid ciphertext
  """
  def decrypt(identity, ciphertext, opts \\ [])

  def decrypt(%__MODULE__{enc_sec: nil}, _ciphertext, _opts), do: {:error, :missing_private_key}

  def decrypt(%__MODULE__{enc_sec: enc_sec, hash: hash}, ciphertext, opts)
      when is_binary(ciphertext) and is_list(opts) do
    try do
      with {:ok, ephemeral_pub, cipher_text} <- split_ciphertext(ciphertext),
           {:ok, ratchets, enforce_ratchets} <- parse_decrypt_opts(opts),
           {:ok, plain_text} <-
             decrypt_payload(
               enc_sec,
               hash,
               ephemeral_pub,
               cipher_text,
               ratchets,
               enforce_ratchets
             ) do
        {:ok, plain_text}
      else
        {:error, :ratchet_enforced} = error -> error
        _ -> {:error, :invalid_ciphertext}
      end
    rescue
      _ ->
        {:error, :invalid_ciphertext}
    end
  end

  def decrypt(%__MODULE__{}, _ciphertext, _opts), do: {:error, :invalid_ciphertext}
  def decrypt(_identity, _ciphertext, _opts), do: {:error, :invalid_ciphertext}

  defp split_ciphertext(ciphertext) when byte_size(ciphertext) > 32 do
    <<ephemeral_pub::binary-size(32), cipher_text::binary>> = ciphertext
    {:ok, ephemeral_pub, cipher_text}
  end

  defp split_ciphertext(_ciphertext), do: {:error, :invalid_ciphertext}

  defp parse_decrypt_opts(opts) do
    ratchets =
      opts
      |> Keyword.get(:ratchets, [])
      |> List.wrap()
      |> Enum.filter(fn ratchet -> is_binary(ratchet) and byte_size(ratchet) == 32 end)

    {:ok, ratchets, Keyword.get(opts, :enforce_ratchets, false) == true}
  end

  defp decrypt_payload(enc_sec, hash, ephemeral_pub, cipher_text, ratchets, enforce_ratchets) do
    case decrypt_with_ratchets(ratchets, ephemeral_pub, cipher_text, hash) do
      {:ok, plain_text} ->
        {:ok, plain_text}

      :error when enforce_ratchets ->
        {:error, :ratchet_enforced}

      :error ->
        case decrypt_with_key(enc_sec, ephemeral_pub, cipher_text, hash) do
          {:ok, plain_text} -> {:ok, plain_text}
          :error -> {:error, :invalid_ciphertext}
        end
    end
  end

  defp decrypt_with_ratchets([], _ephemeral_pub, _cipher_text, _hash), do: :error

  defp decrypt_with_ratchets([ratchet | rest], ephemeral_pub, cipher_text, hash) do
    case decrypt_with_key(ratchet, ephemeral_pub, cipher_text, hash) do
      {:ok, plain_text} -> {:ok, plain_text}
      :error -> decrypt_with_ratchets(rest, ephemeral_pub, cipher_text, hash)
    end
  end

  defp decrypt_with_key(private_key, ephemeral_pub, cipher_text, hash) do
    result =
      %{sec: private_key, pub: ephemeral_pub}
      |> Crypto.compute()
      |> Crypto.hkdf(hash, <<>>, @derived_key_len)
      |> Fernet.new()
      |> Fernet.decrypt(cipher_text)

    case result do
      {:ok, plain_text} -> {:ok, plain_text}
      {:error, _reason} -> :error
    end
  end

  @doc "Signs message bytes with identity Ed25519 private key."
  def sign(%__MODULE__{sig_sec: key}, message) do
    Crypto.sign(key, message)
  end

  @doc "Validates Ed25519 signature for message bytes."
  def validate(%__MODULE__{sig_pub: key}, message, signature) do
    Crypto.validate(key, message, signature)
  end
end
