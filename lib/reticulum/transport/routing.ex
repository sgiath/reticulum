defmodule Reticulum.Transport.Routing do
  @moduledoc false

  @type path_candidate :: %{
          health_score: non_neg_integer(),
          hops: non_neg_integer(),
          interface: atom() | nil,
          updated_at: integer()
        }

  def prefer_candidate?(candidate, nil, _opts), do: valid_candidate?(candidate)

  def prefer_candidate?(candidate, current, opts)
      when is_map(candidate) and is_map(current) and is_list(opts) do
    candidate_health_score = Keyword.get(opts, :candidate_health_score, 100)
    current_health_score = Keyword.get(opts, :current_health_score, 100)

    case compare_health(candidate_health_score, current_health_score) do
      :prefer_candidate ->
        true

      :prefer_current ->
        false

      :tie ->
        prefer_by_metrics?(candidate, current)
    end
  end

  def prefer_candidate?(_candidate, _current, _opts), do: false

  def valid_candidate?(%{hops: hops, updated_at: updated_at, health_score: health_score})
      when is_integer(hops) and hops >= 0 and is_integer(updated_at) and is_integer(health_score) and
             health_score >= 0,
      do: true

  def valid_candidate?(_candidate), do: false

  defp prefer_by_metrics?(candidate, current) do
    case compare_hops(candidate.hops, current.hops) do
      :prefer_candidate ->
        true

      :prefer_current ->
        false

      :tie ->
        prefer_by_freshness?(candidate, current)
    end
  end

  defp prefer_by_freshness?(candidate, current) do
    cond do
      candidate.updated_at > current.updated_at -> true
      candidate.updated_at < current.updated_at -> false
      true -> interface_sort_key(candidate.interface) <= interface_sort_key(current.interface)
    end
  end

  defp compare_health(candidate_health_score, current_health_score)
       when candidate_health_score > current_health_score,
       do: :prefer_candidate

  defp compare_health(candidate_health_score, current_health_score)
       when candidate_health_score < current_health_score,
       do: :prefer_current

  defp compare_health(_candidate_health_score, _current_health_score), do: :tie

  defp compare_hops(candidate_hops, current_hops) when candidate_hops < current_hops,
    do: :prefer_candidate

  defp compare_hops(candidate_hops, current_hops) when candidate_hops > current_hops,
    do: :prefer_current

  defp compare_hops(_candidate_hops, _current_hops), do: :tie

  defp interface_sort_key(interface) when is_atom(interface), do: Atom.to_string(interface)
  defp interface_sort_key(_interface), do: ""
end
