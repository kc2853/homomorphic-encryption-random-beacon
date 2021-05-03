defmodule HerbTest do
  use ExUnit.Case
  doctest Herb
  import Emulation, only: [spawn: 2, send: 2, whoami: 0]

  import Kernel,
    except: [spawn: 3, spawn: 1, spawn_link: 1, spawn_link: 3, send: 2]

  test "Nothing crashes during DKG setup" do
    Emulation.init()
    Emulation.append_fuzzers([Fuzzers.delay(2)])

    t = 6
    n = 10
    # Sample list of safe primes: http://oeis.org/A005385/b005385.txt
    p = 1019
    view = [:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10]
    # Setting the following to 0 to check if DKG works first of all
    round_max = 0
    base_config =
      Herb.new_configuration(t, n, Herb.get_generator(p), p, view, round_max)

    spawn(:p1, fn -> Herb.dkg(base_config) end)
    spawn(:p2, fn -> Herb.dkg(base_config) end)
    spawn(:p3, fn -> Herb.dkg(base_config) end)
    spawn(:p4, fn -> Herb.dkg(base_config) end)
    spawn(:p5, fn -> Herb.dkg(base_config) end)
    spawn(:p6, fn -> Herb.dkg(base_config) end)
    spawn(:p7, fn -> Herb.dkg(base_config) end)
    spawn(:p8, fn -> Herb.dkg(base_config) end)
    spawn(:p9, fn -> Herb.dkg(base_config) end)
    spawn(:p10, fn -> Herb.dkg(base_config) end)

    client =
      spawn(:client, fn ->
        Enum.map(view, fn pid -> send(pid, :dkg) end)

        receive do
        after
          3_000 -> true
        end
      end)

    handle = Process.monitor(client)
    # Timeout.
    receive do
      {:DOWN, ^handle, _, _, _} -> true
    after
      30_000 -> assert false
    end
  after
    Emulation.terminate()
  end

  defp client_listen_loop(herb, round_max) do
    receive do
      {sender, {round, round_output}} ->
        IO.puts "#{inspect(whoami())} Received round #{inspect(round)}, output #{inspect(round_output)}"
        herb = herb ++ [round_output]
        cond do
          # Completion of all the rounds
          round == round_max ->
            IO.puts "#{inspect(whoami())} Final list of outputs #{inspect(herb)}"
            herb
          # Ongoing HERB
          true ->
            client_listen_loop(herb, round_max)
        end
    end
  end

  test "HERB operates as intended when given trivial message delay" do
    Emulation.init()
    Emulation.append_fuzzers([Fuzzers.delay(2)])

    t = 6
    n = 10
    # Sample list of safe primes: http://oeis.org/A005385/b005385.txt
    p = 100043
    view = [:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10]
    round_max = 100
    base_config =
      Herb.new_configuration(t, n, Herb.get_generator(p), p, view, round_max)
    replier_config =
      %{base_config | replier: true}

    spawn(:p1, fn -> Herb.dkg(replier_config) end)
    spawn(:p2, fn -> Herb.dkg(base_config) end)
    spawn(:p3, fn -> Herb.dkg(base_config) end)
    spawn(:p4, fn -> Herb.dkg(base_config) end)
    spawn(:p5, fn -> Herb.dkg(base_config) end)
    spawn(:p6, fn -> Herb.dkg(base_config) end)
    spawn(:p7, fn -> Herb.dkg(base_config) end)
    spawn(:p8, fn -> Herb.dkg(base_config) end)
    spawn(:p9, fn -> Herb.dkg(base_config) end)
    spawn(:p10, fn -> Herb.dkg(base_config) end)

    client =
      spawn(:client, fn ->
        start = :os.system_time(:millisecond)
        Enum.map(view, fn pid -> send(pid, :dkg) end)
        herb = client_listen_loop([], round_max)
        assert Enum.count(herb) == round_max
        finish = :os.system_time(:millisecond)
        IO.puts "Total time taken: #{finish - start} ms"
      end)

    handle = Process.monitor(client)
    # Timeout.
    receive do
      {:DOWN, ^handle, _, _, _} -> true
    after
      30_000 -> assert false
    end
  after
    Emulation.terminate()
  end
end
