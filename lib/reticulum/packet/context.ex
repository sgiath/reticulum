defmodule Reticulum.Packet.Context do
  @moduledoc """
  Packet context constants and normalization helpers.
  """

  @none 0x00
  @resource 0x01
  @resource_adv 0x02
  @resource_req 0x03
  @resource_hmu 0x04
  @resource_prf 0x05
  @resource_icl 0x06
  @resource_rcl 0x07
  @cache_request 0x08
  @request 0x09
  @response 0x0A
  @path_response 0x0B
  @command 0x0C
  @command_status 0x0D
  @channel 0x0E
  @keepalive 0xFA
  @linkidentify 0xFB
  @linkclose 0xFC
  @linkproof 0xFD
  @lrrtt 0xFE
  @lrproof 0xFF

  @all [
    @none,
    @resource,
    @resource_adv,
    @resource_req,
    @resource_hmu,
    @resource_prf,
    @resource_icl,
    @resource_rcl,
    @cache_request,
    @request,
    @response,
    @path_response,
    @command,
    @command_status,
    @channel,
    @keepalive,
    @linkidentify,
    @linkclose,
    @linkproof,
    @lrrtt,
    @lrproof
  ]

  @encryption_exempt [@resource, @keepalive, @cache_request]

  def all, do: @all
  def none, do: @none
  def resource, do: @resource
  def resource_adv, do: @resource_adv
  def resource_req, do: @resource_req
  def resource_hmu, do: @resource_hmu
  def resource_prf, do: @resource_prf
  def resource_icl, do: @resource_icl
  def resource_rcl, do: @resource_rcl
  def cache_request, do: @cache_request
  def request, do: @request
  def response, do: @response
  def path_response, do: @path_response
  def command, do: @command
  def command_status, do: @command_status
  def channel, do: @channel
  def keepalive, do: @keepalive
  def linkidentify, do: @linkidentify
  def linkclose, do: @linkclose
  def linkproof, do: @linkproof
  def lrrtt, do: @lrrtt
  def lrproof, do: @lrproof

  def normalize(context) when is_integer(context) and context in 0..255, do: {:ok, context}
  def normalize(<<context>>) when context in 0..255, do: {:ok, context}
  def normalize(_context), do: {:error, :invalid_packet_context}

  def encryption_exempt?(context) do
    case normalize(context) do
      {:ok, value} -> value in @encryption_exempt
      _ -> false
    end
  end
end
