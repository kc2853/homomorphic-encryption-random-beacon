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
    # Prime number (must be a safe prime: https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes)
    p: nil,
    # Prime number equal to (p - 1) / 2
    q: nil,
    # List of pids
    view: nil,
    # Map of pid to id
    view_id: nil,
    # Subshare from each node
    view_subshare: nil,
    # Subsignature from each node for all rounds
    view_subsign: nil,
    # Individual share used to make subsignatures for DRB
    share: nil,
    # Max number of rounds for DRB
    round_max: nil,
    # Current round for DRB
    round_current: nil,
    # Random number from the previous round
    last_output: nil,
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
        round_max,
        last_output
      ) do
    q = trunc((p - 1) / 2)
    view_id = Enum.with_index(view, 1) |> Map.new()
    view_subshare = Enum.map(view, fn a -> {a, nil} end) |> Map.new()
    view_subsign = 1..round_max |> Enum.map(fn n ->
                                     {n, Enum.map(view, fn a -> {a, nil} end) |> Map.new()}
                                   end)
                                |> Map.new()
    %Herb{
      t: t,
      n: n,
      g: g,
      p: p,
      q: q,
      view: view,
      view_id: view_id,
      view_subshare: view_subshare,
      view_subsign: view_subsign,
      round_max: round_max,
      round_current: 0,
      last_output: last_output,
      replier: false,
      byzantine: false
    }
  end

  # Generator (primitive root) of Z_q where q is a prime number equal to (p - 1) / 2
  def get_generator(p) do
    get_generator(p, 2)
  end

  # Algorithm 4.86 from http://cacr.uwaterloo.ca/hac/about/chap4.pdf
  defp get_generator(p, x) do
    cond do
      # Find a generator of (Z_p)* first
      # then square it to get a generator of Z_q
      :maths.mod_exp(x, 2, p) != 1 && :maths.mod_exp(x, trunc((p - 1) / 2), p) != 1 ->
        # IO.puts "Generator: #{inspect(:maths.mod_exp(x, 2, p))}"
        :maths.mod_exp(x, 2, p)
      true ->
        get_generator(p, x + 1)
    end
  end

  # We start n parallel instances of VSS (verifiable secret sharing)
  def get_poly_then_send(state) do
    # Generate t number of random coefficients in (Z_p)*
    coeff = Enum.map(1..state.t, fn _ -> :rand.uniform(state.p - 1) end)
    comm = get_comm(coeff, state.g, state.p)

    # Correctly send corresponding subshares to each node
    state.view
    |> Enum.filter(fn pid -> pid != whoami() end)
    |> Enum.map(fn pid ->
         id = Map.get(state.view_id, pid)
         subshare = get_subshare(coeff, id)
         msg = {subshare, comm}
         send(pid, msg)
       end)

    # Calculate my subshare and update state
    id_me = Map.get(state.view_id, whoami())
    subshare_me = get_subshare(coeff, id_me)
    state = %{state | view_subshare: Map.put(state.view_subshare, whoami(), subshare_me)}
    state
  end

  # We commit to coefficients by raising g (group generator) to the power of each coefficient
  def get_comm(coeff, g, p) do
    # :maths belongs to ndpar library
    Enum.map(coeff, fn x -> :maths.mod_exp(g, x, p) end)
  end

  # Horner's method for polynomial evaluation (at id)
  def get_subshare(coeff, id) do
    Enum.reduce(Enum.reverse(coeff), 0, fn x, acc -> x + acc * id end)
  end

  # Verify a subshare as per VSS (verifiable secret sharing)
  def verify_subshare(subshare, comm, g, p, id) do
    lhs = :maths.mod_exp(g, subshare, p)
    rhs = Enum.with_index(comm)
    rhs = Enum.map(rhs, fn t -> :maths.mod_exp(elem(t, 0), :maths.pow(id, elem(t, 1)), p) end)
    rhs = Enum.reduce(rhs, fn x, acc -> :maths.mod(x * acc, p) end)
    lhs == rhs
  end

  # Above are utility functions before DKG
  # Below is DKG

  # Distributed key generation
  def dkg(state) do
    dkg(state, 0)
  end

  # Counter counts how many subshares one has received so far (need n)
  # Note (QUAL assumption): In the literature, the usual assumption is that some nodes could be
  # unresponsive/faulty/Byzantine in the DKG phase (pre-DRB phase), in which case
  # nodes first need to agree on a group of qualified nodes (denoted by QUAL) during DKG.
  # Here, we assume that all initialized nodes are honest and fully functional
  # in the DKG phase (perhaps not in the DRB phase later though). In other words,
  # all nodes are in QUAL, so the number of nodes in QUAL is n.
  defp dkg(state, counter) do
    nil
  end
end
