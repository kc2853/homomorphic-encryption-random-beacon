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
    # Sample list of safe primes: [5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587, 719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823, 1907]
    p = 1019
    view = [:p1, :p2, :p3, :p4, :p5, :p6, :p7, :p8, :p9, :p10]
    # Setting the following to 0 to check if DKG works first of all
    round_max = 0
    base_config =
      Herb.new_configuration(t, n, Herb.get_generator(p), p, view, round_max, "HERB")

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
end
