defmodule Herb do
  @moduledoc """
  An implementation of the HERB (homomorphic encryption random beacon) protocol.
  """
  import Emulation, only: [send: 2, whoami: 0]
  import Kernel, except: [spawn: 3, spawn: 1, spawn_link: 1, spawn_link: 3, send: 2]
  require Fuzzers
  require Logger

  # This structure contains all the process state
  # required by the HERB protocol.
  defstruct(
    # Threshold
    t: nil,
    # Number of participants
    n: nil,
    # Group generator of Z_q where q is prime
    g: nil,
    # Group public key
    h: nil,
    # Prime number (must be a safe prime: https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes)
    p: nil,
    # Prime number equal to (p - 1) / 2
    q: nil,
    # List of pids
    view: nil,
    # Map of pid to id
    view_id: nil,
    # Subshare and individual public key from each node
    view_subshare_and_pk: nil,
    # Individual share from received subshares
    share: nil,
    # Subciphertext from each node for all rounds
    view_subciphertext: nil,
    # Subdecryption from each node for all rounds
    view_subdecryption: nil,
    # Max number of rounds for HERB
    round_max: nil,
    # Current round for HERB
    round_current: nil,
    # Replier replies to client with each round's random number (for demonstration purposes)
    replier: nil,
    # Client receiving the sequence of random numbers (for demonstration purposes)
    client: nil,
    # Byzantine nodes (for demonstration purposes)
    byzantine: nil
  )

  def new_configuration(
        t,
        n,
        g,
        p,
        view,
        round_max
      ) do
    q = trunc((p - 1) / 2)
    view_id = Enum.with_index(view, 1) |> Map.new()
    view_subshare_and_pk = Enum.map(view, fn a -> {a, nil} end) |> Map.new()
    view_subciphertext = 1..round_max
    |> Enum.map(fn n -> {n, Enum.map(view, fn a -> {a, nil} end) |> Map.new()} end)
    |> Map.new()
    view_subdecryption = 1..round_max
    |> Enum.map(fn n -> {n, Enum.map(view, fn a -> {a, nil} end) |> Map.new()} end)
    |> Map.new()
    %Herb{
      t: t,
      n: n,
      g: g,
      p: p,
      q: q,
      view: view,
      view_id: view_id,
      view_subshare_and_pk: view_subshare_and_pk,
      view_subciphertext: view_subciphertext,
      view_subdecryption: view_subdecryption,
      round_max: round_max,
      round_current: 0,
      replier: false,
      byzantine: false
    }
  end

  # Generator (primitive root) of Z_q where q is a prime number equal to (p - 1) / 2
  def get_generator(p) do
    get_generator(p, 2)
  end

  # Algorithm 4.86 from http://cacr.uwaterloo.ca/hac/about/chap4.pdf
  # :maths belongs to ndpar library
  defp get_generator(p, x) do
    cond do
      # Find a generator of (Z_p)* first
      # then square it to get a generator of Z_q
      :maths.mod_exp(x, 2, p) != 1 && :maths.mod_exp(x, trunc((p - 1) / 2), p) != 1 ->
        :maths.mod_exp(x, 2, p)
      true ->
        get_generator(p, x + 1)
    end
  end

  # We commit to coefficients by raising g (group generator) to the power of each coefficient
  def get_comm(coeff, g, p) do
    Enum.map(coeff, fn x -> :maths.mod_exp(g, x, p) end)
  end

  # Horner's method for polynomial evaluation (at id)
  def get_subshare(coeff, id, q) do
    # Concern: calculate mod q inside not outside?
    :maths.mod(Enum.reduce(Enum.reverse(coeff), 0, fn x, acc -> x + acc * id end), q)
  end

  # We start n parallel instances of VSS (verifiable secret sharing)
  def get_poly_then_send(state) do
    coeff = Enum.map(1..state.t, fn _ -> :rand.uniform(state.q) end)
    comm = get_comm(coeff, state.g, state.p)

    # Correctly send corresponding subshares to each node
    state.view
    |> Enum.filter(fn pid -> pid != whoami() end)
    |> Enum.map(fn pid ->
         id = Map.get(state.view_id, pid)
         subshare = get_subshare(coeff, id, state.q)
         msg = {subshare, comm}
         send(pid, msg)
       end)

    # Calculate my subshare and update state
    id_me = Map.get(state.view_id, whoami())
    subshare_me = get_subshare(coeff, id_me, state.q)
    state = %{state | view_subshare_and_pk: Map.put(state.view_subshare_and_pk, whoami(), {subshare_me, List.first(comm)})}
    state
  end

  # Verify a subshare as per VSS (verifiable secret sharing)
  def verify_subshare(subshare, comm, g, p, id) do
    lhs = :maths.mod_exp(g, subshare, p)
    rhs = Enum.with_index(comm)
    # Concern: change pow to mod q?
    rhs = Enum.map(rhs, fn t -> :maths.mod_exp(elem(t, 0), :maths.pow(id, elem(t, 1)), p) end)
    rhs = Enum.reduce(rhs, fn x, acc -> :maths.mod(x * acc, p) end)
    lhs == rhs
  end

  # Distributed key generation
  def dkg(state) do
    dkg(state, 0)
  end

  defp dkg(state, counter) do
    receive do
      # Receive start order for DKG
      {sender, :dkg} ->
        IO.puts "#{inspect(whoami())} Received :dkg"
        state = %{state | client: sender}
        state = get_poly_then_send(state)
        counter = counter + 1
        cond do
          # This can happen if the network is highly unstable such that the :dkg message
          # from the client reaches a node last (compared to subshare messages)
          counter == state.n ->
            {p, q} = {state.p, state.q}
            {share, h} = Map.values(state.view_subshare_and_pk)
            |> Enum.reduce(fn x, acc -> {:maths.mod(elem(acc, 0) + elem(x, 0), q), :maths.mod(elem(acc, 1) * elem(x, 1), p)} end)
            state = %{state | share: share, h: h}
            IO.puts "#{inspect(whoami())} Exits DKG due to #{inspect(sender)}, share #{state.share} h #{state.h}"
            herb_new_round(state)
          # Normal cases
          true ->
            dkg(state, counter)
        end

      # Listen loop for subshares
      {sender, {subshare, comm}} ->
        # IO.puts "#{inspect(whoami())} Received subshare from #{inspect(sender)}"
        id_me = Map.get(state.view_id, whoami())
        case verify_subshare(subshare, comm, state.g, state.p, id_me) do
          false ->
            raise "DKG verify shouldn't fail"
          # Normal cases
          true ->
            state = %{state | view_subshare_and_pk: Map.put(state.view_subshare_and_pk, sender, {subshare, List.first(comm)})}
            counter = counter + 1
            cond do
              # Need to wait for more subshares
              counter < state.n ->
                dkg(state, counter)
              # Can make a share out of all subshares received
              true ->
                {p, q} = {state.p, state.q}
                {share, h} = Map.values(state.view_subshare_and_pk)
                |> Enum.reduce(fn x, acc -> {:maths.mod(elem(acc, 0) + elem(x, 0), q), :maths.mod(elem(acc, 1) * elem(x, 1), p)} end)
                state = %{state | share: share, h: h}
                IO.puts "#{inspect(whoami())} Exits DKG due to #{inspect(sender)}, share #{state.share} h #{state.h}"
                herb_new_round(state)
            end
        end
    end
  end

  ##########################################
  # End of DKG phase
  # Start of beacon phase
  ##########################################

  def get_dleq_nizk(g1, h1, g2, h2, p, q, share) do
    w = :rand.uniform(q)
    a1 = :maths.mod_exp(g1, w, p)
    a2 = :maths.mod_exp(g2, w, p)
    params = ["#{h1}", "#{h2}", "#{a1}", "#{a2}"]
    c = :crypto.hash(:sha224, params) |> :binary.decode_unsigned |> :maths.mod(q)
    r = :maths.mod(w - share * c, q)
    {a1, a2, r}
  end

  def verify_dleq_nizk(g1, h1, g2, h2, p, q, nizk) do
    {a1, a2, r} = nizk
    lhs1 = a1
    lhs2 = a2
    params = ["#{h1}", "#{h2}", "#{a1}", "#{a2}"]
    c = :crypto.hash(:sha224, params) |> :binary.decode_unsigned |> :maths.mod(q)
    rhs1 = :maths.mod_exp(g1, r, p) * :maths.mod_exp(h1, c, p) |> :maths.mod(p)
    rhs2 = :maths.mod_exp(g2, r, p) * :maths.mod_exp(h2, c, p) |> :maths.mod(p)
    lhs1 == rhs1 && lhs2 == rhs2
  end

  def get_schnorr_nizk(g, g_to_r, p, q, r) do
    w = :rand.uniform(q)
    u = :maths.mod_exp(g, w, p)
    params = ["#{g}", "#{g_to_r}", "#{u}"]
    c = :crypto.hash(:sha224, params) |> :binary.decode_unsigned |> :maths.mod(q)
    z = :maths.mod(w + c * r, q)
    {u, c, z}
  end

  def verify_schnorr_nizk(g, g_to_r, p, q, nizk) do
    {u, c, z} = nizk
    lhs1 = c
    lhs2 = :maths.mod_exp(g, z, p)
    params = ["#{g}", "#{g_to_r}", "#{u}"]
    rhs1 = :crypto.hash(:sha224, params) |> :binary.decode_unsigned |> :maths.mod(q)
    rhs2 = :maths.mod(u * :maths.mod_exp(g_to_r, c, p), p)
    lhs1 == rhs1 && lhs2 == rhs2
  end

  def get_lambda(lambda_set, i, q) do
    # We work with modulo q (not p) when dealing with exponents
    Enum.filter(lambda_set, fn x -> x != i end)
    |> Enum.map(fn j ->
         # Below `cond do` is b/c :maths.mod_inv() cannot deal with negative numbers
         cond do
           j / (j - i) < 0 ->
             # Can't perform :maths.mod_inv() if q is not prime
             :maths.mod(-j, q) * :maths.mod_inv(i - j, q)
           j / (j - i) > 0 ->
             :maths.mod(j, q) * :maths.mod_inv(j - i, q)
           true ->
             raise "Should not get any zero when calculating lambda"
         end
       end)
    |> Enum.reduce(fn x, acc -> :maths.mod(x * acc, q) end)
  end

  def get_decryption(subdecryptions, p, q) do
    lambda_set = Enum.map(subdecryptions, fn x -> elem(x, 0) end)
    Enum.map(subdecryptions, fn x ->
      subdecryption = elem(x, 1)
      lambda = get_lambda(lambda_set, elem(x, 0), q)
      :maths.mod_exp(subdecryption, lambda, p)
    end)
    |> Enum.reduce(fn x, acc -> :maths.mod(x * acc, p) end)
  end

  def get_new_view_subciphertext(view, round, pid, subciphertext) do
    res = Map.put(view[round], pid, subciphertext)
    Map.put(view, round, res)
  end

  def get_new_view_subdecryption(view, round, pid, subdecryption) do
    res = Map.put(view[round], pid, subdecryption)
    Map.put(view, round, res)
  end

  def herb_new_round(state) do
    state = %{state | round_current: state.round_current + 1}
    cond do
      # Successful completion of HERB
      state.round_current > state.round_max ->
        IO.puts "#{inspect(whoami())} Protocol successfully completed!"
        nil
      # Ongoing beacon
      true ->
        {p, q, g, h} = {state.p, state.q, state.g, state.h}
        r_k = :rand.uniform(q)
        m_k = :rand.uniform(p - 1)
        nizk = get_schnorr_nizk(g, :maths.mod_exp(g, r_k, p), p, q, r_k)
        a_k = :maths.mod_exp(g, r_k, p)
        b_k = :maths.mod(m_k * :maths.mod_exp(h, r_k, p), p)
        msg = {a_k, b_k, nizk, state.round_current}

        # Broadcasting
        state.view
        |> Enum.filter(fn pid -> pid != whoami() end)
        |> Enum.map(fn pid -> send(pid, msg) end)

        # Update own state
        new = get_new_view_subciphertext(state.view_subciphertext, state.round_current, whoami(), {a_k, b_k})
        state = %{state | view_subciphertext: new}
        herb(state)
    end
  end

  def herb(state) do
    receive do
      {sender, {a_k, b_k, nizk, round}} ->
        cond do
          # Ignore past round
          round < state.round_current ->
            herb(state)
          # Check if NIZK returns true
          verify_schnorr_nizk(state.g, a_k, state.p, state.q, nizk) == false ->
            IO.puts "#{inspect(whoami())} Invalid NIZK"
            herb(state)
          # Message from a future round
          round > state.round_current ->
            new = get_new_view_subciphertext(state.view_subciphertext, round, sender, {a_k, b_k})
            state = %{state | view_subciphertext: new}
            herb(state)
          # Message from the current round
          true ->
            new = get_new_view_subciphertext(state.view_subciphertext, round, sender, {a_k, b_k})
            state = %{state | view_subciphertext: new}
            count_subciphertext = Map.values(state.view_subciphertext[state.round_current]) |> Enum.count(fn x -> x != nil end)
            cond do
              count_subciphertext < state.n ->
                herb(state)
              true ->
                herb_send_decryption(state)
            end
        end

      {sender, {subdecryption, nizk_msg, round}} ->
        {nizk, g_to_share, a} = nizk_msg
        cond do
          # Ignore past round
          round < state.round_current ->
            herb(state)
          # Check if NIZK returns true
          verify_dleq_nizk(state.g, g_to_share, a, subdecryption, state.p, state.q, nizk) == false ->
            IO.puts "#{inspect(whoami())} Invalid NIZK"
            herb(state)
          # Message from a future round
          round > state.round_current ->
            new = get_new_view_subdecryption(state.view_subdecryption, round, sender, subdecryption)
            state = %{state | view_subdecryption: new}
            herb(state)
          # Message from the current round
          true ->
            new = get_new_view_subdecryption(state.view_subdecryption, round, sender, subdecryption)
            state = %{state | view_subdecryption: new}
            count_subdecryption = Map.values(state.view_subdecryption[state.round_current]) |> Enum.count(fn x -> x != nil end)
            count_subciphertext = Map.values(state.view_subciphertext[state.round_current]) |> Enum.count(fn x -> x != nil end)
            cond do
              count_subdecryption < state.t ->
                herb(state)
              # Edge case: t number of subdecryption earlier than n number of subciphertext
              # Concern: slowest subciphertext sender is still the bottleneck right now
              count_subciphertext < state.n ->
                herb(state)
              true ->
                herb_end_round(state)
            end
        end
    end
  end

  def herb_send_decryption(state) do
    a = Map.to_list(state.view_subciphertext[state.round_current])
    |> Enum.map(fn x -> elem(elem(x, 1), 0) end)
    |> Enum.reduce(fn x, acc -> :maths.mod(x * acc, state.p) end)
    subdecryption = a |> :maths.mod_exp(state.share, state.p)
    g_to_share = :maths.mod_exp(state.g, state.share, state.p)
    nizk = get_dleq_nizk(state.g, g_to_share, a, subdecryption, state.p, state.q, state.share)
    nizk_msg = {nizk, g_to_share, a}
    msg = {subdecryption, nizk_msg, state.round_current}

    # Broadcasting
    state.view
    |> Enum.filter(fn pid -> pid != whoami() end)
    |> Enum.map(fn pid -> send(pid, msg) end)

    # Update own state
    new = get_new_view_subdecryption(state.view_subdecryption, state.round_current, whoami(), subdecryption)
    state = %{state | view_subdecryption: new}
    herb(state)
  end

  def herb_end_round(state) do
    subdecryptions = Map.to_list(state.view_subdecryption[state.round_current])
    |> Enum.filter(fn x -> elem(x, 1) != nil end)
    |> Enum.map(fn x -> {Map.get(state.view_id, elem(x, 0)), elem(x, 1)} end)
    # Lagrange interpolation
    decryption = get_decryption(subdecryptions, state.p, state.q)
    # IO.puts "#{inspect(whoami())} Round #{state.round_current} view_subciphertext: #{inspect(Map.to_list(state.view_subciphertext[state.round_current]))}"
    b = Map.to_list(state.view_subciphertext[state.round_current])
    |> Enum.map(fn x -> elem(elem(x, 1), 1) end)
    |> Enum.reduce(fn x, acc -> :maths.mod(x * acc, state.p) end)
    round_output = :maths.mod(b * :maths.mod_inv(decryption, state.p), state.p)
    round_output = :crypto.hash(:sha256, ["#{round_output}"]) |> :binary.decode_unsigned |> :maths.mod(state.p)
    # IO.puts "#{inspect(whoami())} Output for round #{inspect(state.round_current)} is #{inspect(round_output)}"

    cond do
      # Send the randomness beacon output to client (for dev purposes)
      state.replier == true ->
        send(state.client, {state.round_current, round_output})
        herb_new_round(state)
      # Normal cases
      true ->
        herb_new_round(state)
    end
  end
end
