import csv
import json
import pprint
import time

import matplotlib.pyplot as plt
import numpy as np

Poly = np.polynomial.polynomial.Polynomial


COLORS = ["red", "green", "blue", "orange", "purple", "gray"]


def plot_time(data, name, title):
    xs = data["x"]
    ys = data["ys"]
    sizes = data["sizes"]

    packet_nums = [*sorted(set(xs))]

    fig, ax = plt.subplots()
    for i, size in enumerate(sizes):
        y_means = []

        for packet_num in packet_nums:
            xy = [(x, y) for (x, y) in zip(xs, ys[str(size)]) if x == packet_num]
            y = np.array([xy[1] for xy in xy])
            y_means.append(np.mean(y))

        ax.plot(xs, ys[str(size)], "o", color=COLORS[i], alpha=0.3, label="Runtime")
        ax.plot(packet_nums, y_means, "--", color=COLORS[i], alpha=0.3, linewidth=2, label="Runtime (average)")

    ax.set_title(title)
    ax.set_xlim(min(packet_nums) / 2, 2 * max(packet_nums))

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Execution time /s")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.legend()

    fig.savefig(name, dpi=fig.dpi * 2)


def plot_throughput(data, name, title):
    xs = data["x"]
    ys = data["ys"]
    sizes = data["sizes"]

    packet_nums = [*sorted(set(xs))]

    fig, ax = plt.subplots()
    for i, size in enumerate(sizes):
        pps_means = []

        for packet_num in packet_nums:
            xy = [(x, y) for (x, y) in zip(xs, ys[str(size)]) if x == packet_num]
            x = np.array([xy[0] for xy in xy])
            y = np.array([xy[1] for xy in xy])
            pps = x / y
            pps_means.append(np.mean(pps))

        y = np.array(ys[str(size)])
        pps = xs / y

        ax.plot(xs, pps, "o", color=COLORS[i], alpha=0.3, label="Throughput")
        ax.plot(packet_nums, pps_means, "--", color=COLORS[i], alpha=0.3, linewidth=2, label="Throughput (average)")

    ax.set_title(title)
    ax.set_xlim(min(packet_nums) / 2, 2 * max(packet_nums))

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Throughput /(packets/s)")

    ax.set_xscale("log")
    ax.legend()

    fig.savefig(name, dpi=fig.dpi * 2)


def plot2_time(py_data, wg_data, suffix):
    py_xs = py_data["x"]
    py_ys = py_data["ys"]
    py_sizes = py_data["sizes"]

    wg_xs = wg_data["x"]
    wg_ys = wg_data["ys"]
    wg_sizes = wg_data["sizes"]

    assert py_sizes == wg_sizes
    packet_nums = [*sorted(set.union(set(py_xs), set(wg_xs)))]

    fig, ax = plt.subplots()
    for i, size in enumerate(py_sizes):
        py_means = []
        wg_means = []

        for packet_num in packet_nums:
            py_xy = [(x, y) for (x, y) in zip(py_xs, py_ys[str(size)]) if x == packet_num]
            py_y = np.array([xy[1] for xy in py_xy])
            py_means.append(np.mean(py_y))

            wg_xy = [(x, y) for (x, y) in zip(wg_xs, wg_ys[str(size)]) if x == packet_num]
            wg_y = np.array([xy[1] for xy in wg_xy])
            wg_means.append(np.mean(wg_y))

        py_color = COLORS[i]
        ax.plot(py_xs, py_ys[str(size)], "o", color=py_color, alpha=0.3, label="Python asyncio")
        ax.plot(packet_nums, py_means, "--", color=py_color, alpha=0.3, linewidth=2, label="Python asyncio (average)")

        wg_color = COLORS[len(COLORS) - i - 1]
        ax.plot(wg_xs, wg_ys[str(size)], "o", color=wg_color, alpha=0.3, label="mitmproxy_wireguard")
        ax.plot(
            packet_nums, wg_means, "--", color=wg_color, alpha=0.3, linewidth=2, label="mitmproxy_wireguard (average)"
        )

    ax.set_title("Echo server runtime comparison")
    ax.set_xlim(min(packet_nums) / 2, 2 * max(packet_nums))

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Execution time /s")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.legend()

    fig.savefig(f"comp_data_{suffix}.png", dpi=fig.dpi * 2)


def plot2_throughput(py_data, wg_data, suffix):
    py_xs = py_data["x"]
    py_ys = py_data["ys"]
    py_sizes = py_data["sizes"]

    wg_xs = wg_data["x"]
    wg_ys = wg_data["ys"]
    wg_sizes = wg_data["sizes"]

    assert py_sizes == wg_sizes
    packet_nums = [*sorted(set.union(set(py_xs), set(wg_xs)))]

    fig, ax = plt.subplots()
    for i, size in enumerate(py_sizes):
        py_means = []
        wg_means = []

        for packet_num in packet_nums:
            py_xy = [(x, y) for (x, y) in zip(py_xs, py_ys[str(size)]) if x == packet_num]
            py_x = np.array([xy[0] for xy in py_xy])
            py_y = np.array([xy[1] for xy in py_xy])
            py_means.append(np.mean(py_x / py_y))

            wg_xy = [(x, y) for (x, y) in zip(wg_xs, wg_ys[str(size)]) if x == packet_num]
            wg_x = np.array([xy[0] for xy in wg_xy])
            wg_y = np.array([xy[1] for xy in wg_xy])
            wg_means.append(np.mean(wg_x / wg_y))

        py_y = np.array(py_ys[str(size)])
        wg_y = np.array(wg_ys[str(size)])

        py_pps = py_xs / py_y
        wg_pps = wg_xs / wg_y

        py_max = np.max(py_pps)
        wg_max = np.max(wg_pps)

        py_color = COLORS[i]
        ax.plot(py_xs, py_pps, "o", color=py_color, alpha=0.3, label="Python asyncio")
        ax.plot(packet_nums, py_means, "--", color=py_color, alpha=0.3, linewidth=2, label="Python asyncio (average)")
        ax.hlines(
            xmin=1e2,
            xmax=1e6,
            y=py_max,
            linestyles="solid",
            color=py_color,
            alpha=0.3,
            linewidth=2,
            label="Python asyncio (best)",
        )

        wg_color = COLORS[len(COLORS) - i - 1]
        ax.plot(wg_xs, wg_pps, "o", color=wg_color, alpha=0.3, label="mitmproxy_wireguard")
        ax.plot(
            packet_nums, wg_means, "--", color=wg_color, alpha=0.3, linewidth=2, label="mitmproxy_wireguard (average)"
        )
        ax.hlines(
            xmin=1e2,
            xmax=1e6,
            y=wg_max,
            linestyles="solid",
            color=wg_color,
            alpha=0.3,
            linewidth=2,
            label="mitmproxy_wireguard (best)",
        )

    ax.set_title("Echo server throughput comparison")
    ax.set_xlim(min(packet_nums) / 2, 2 * max(packet_nums))

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Throughput /(packets/s)")

    ax.set_xscale("log")
    ax.legend()

    fig.savefig(f"comp_tp_{suffix}.png", dpi=fig.dpi * 2)


def stats_throughput(py_data, wg_data, suffix):
    py_xs = py_data["x"]
    py_ys = py_data["ys"]
    py_sizes = py_data["sizes"]

    wg_xs = wg_data["x"]
    wg_ys = wg_data["ys"]
    wg_sizes = wg_data["sizes"]

    assert py_sizes == wg_sizes

    packet_nums = [*sorted(set.union(set(wg_xs), set(py_xs)))]

    print(suffix)
    for size in py_sizes:
        py_file = open(f"py_{suffix}_{size}B.csv", "w", newline="")
        wg_file = open(f"wg_{suffix}_{size}B.csv", "w", newline="")

        columns = ["packets", "tp_avg", "tp_sdv", "tp_min", "tp_max"]
        py_csv = csv.DictWriter(py_file, columns, delimiter=",")
        wg_csv = csv.DictWriter(wg_file, columns, delimiter=",")

        py_csv.writeheader()
        wg_csv.writeheader()

        for packet_num in packet_nums:
            py_xy = [(x, y) for (x, y) in zip(py_xs, py_ys[str(size)]) if x == packet_num]
            wg_xy = [(x, y) for (x, y) in zip(wg_xs, wg_ys[str(size)]) if x == packet_num]

            py_x = np.array([xy[0] for xy in py_xy])
            py_y = np.array([xy[1] for xy in py_xy])
            wg_x = np.array([xy[0] for xy in wg_xy])
            wg_y = np.array([xy[1] for xy in wg_xy])

            py_pps = py_x / py_y
            wg_pps = wg_x / wg_y

            py_mean = np.mean(py_pps)
            py_sdev = np.std(py_pps)
            py_min = np.min(py_pps)
            py_max = np.max(py_pps)

            wg_mean = np.mean(wg_pps)
            wg_min = np.min(wg_pps)
            wg_max = np.max(wg_pps)
            wg_sdev = np.std(wg_pps)

            print(" \tnum\tavg\tsdv\tmin\tmax")
            print(f"py\t{packet_num}\t{py_mean}\t{py_sdev}\t{py_min}\t{py_max}")
            print(f"wg\t{packet_num}\t{wg_mean}\t{wg_sdev}\t{wg_min}\t{wg_max}")

            py_csv.writerow(dict(packets=packet_num, tp_avg=py_mean, tp_sdv=py_sdev, tp_min=py_min, tp_max=py_max))
            wg_csv.writerow(dict(packets=packet_num, tp_avg=wg_mean, tp_sdv=wg_sdev, tp_min=wg_min, tp_max=wg_max))

        py_x = np.array(py_xs)
        py_y = np.array(py_ys[str(size)])

        wg_x = np.array(wg_xs)
        wg_y = np.array(wg_ys[str(size)])

        py_pps = py_x / py_y
        wg_pps = wg_x / wg_y

        py_mean = np.mean(py_pps)
        py_sdev = np.std(py_pps)
        py_min = np.min(py_pps)
        py_max = np.max(py_pps)

        wg_mean = np.mean(wg_pps)
        wg_min = np.min(wg_pps)
        wg_max = np.max(wg_pps)
        wg_sdev = np.std(wg_pps)

        print(" \ttotal\tavg\tsdv\tmin\tmax")
        print(f"py\t \t{py_mean}\t{py_sdev}\t{py_min}\t{py_max}")
        print(f"wg\t \t{wg_mean}\t{wg_sdev}\t{wg_min}\t{wg_max}")

        py_csv.writerow(dict(packets="total", tp_avg=py_mean, tp_sdv=py_sdev, tp_min=py_min, tp_max=py_max))
        wg_csv.writerow(dict(packets="total", tp_avg=wg_mean, tp_sdv=wg_sdev, tp_min=wg_min, tp_max=wg_max))

        py_file.close()
        wg_file.close()


def main():
    for suffix in ["local", "nonlocal"]:

        with open(f"py_data_{suffix}.json") as file:
            py_data = json.load(file)

        with open(f"wg_data_{suffix}.json") as file:
            wg_data = json.load(file)

        # plot raw runtime data
        plot_time(py_data, f"py_data_{suffix}.png", "Python asyncio")
        plot_time(wg_data, f"wg_data_{suffix}.png", "mitmproxy_wireguard")

        # plot throughput data
        plot_throughput(py_data, f"py_tp_{suffix}.png", "Python asyncio")
        plot_throughput(wg_data, f"wg_tp_{suffix}.png", "mitmproxy_wireguard")

        # plot runtime and throughput comparisons
        plot2_time(py_data, wg_data, suffix)
        plot2_throughput(py_data, wg_data, suffix)

        # write throughput statistics
        stats_throughput(py_data, wg_data, suffix)


if __name__ == "__main__":
    main()
