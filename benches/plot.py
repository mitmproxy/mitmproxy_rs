import json
import pprint
import time

import matplotlib.pyplot as plt
import numpy as np

Poly = np.polynomial.polynomial.Polynomial


COLORS = ["red", "green", "blue", "orange", "purple", "gray"]


def plot_time(data, name, title):
    x = data["x"]
    ys = data["ys"]
    sizes = data["sizes"]

    fig, ax = plt.subplots()
    for i, size in enumerate(sizes):
        d, k = Poly.fit(x, ys[str(size)], 1).convert().coef

        xhat = np.logspace(3, 5)
        yhat = xhat * k + d

        ax.plot(x, ys[str(size)], "o", color=COLORS[i], alpha=0.3, label="Measured runtime")
        ax.plot(xhat, yhat, "-", color=COLORS[i], label="Linear model")

    ax.set_title(title)

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Execution time /s")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.legend()

    fig.savefig(name, dpi=fig.dpi * 2)


def plot_throughput(data, name, title):
    x = data["x"]
    ys = data["ys"]
    sizes = data["sizes"]

    fig, ax = plt.subplots()
    for i, size in enumerate(sizes):
        y = np.array(ys[str(size)])
        d, k = Poly.fit(x, y, 1).convert().coef
        pps = x / y

        xhat = np.logspace(3, 5)
        yhat = xhat / (xhat * k + d)

        ax.plot(x, pps, "o", color=COLORS[i], alpha=0.3, label="Measured throughput")
        ax.plot(xhat, yhat, "-", color=COLORS[i], label="Linear model")
        ax.hlines(
            xmin=1e3,
            xmax=1e5,
            y=1 / k,
            linestyles="dashed",
            color=COLORS[i],
            alpha=0.3,
            linewidth=2,
            label="Estimated maximum throughput",
        )

    ax.set_title(title)

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Throughput /(packets/s)")

    ax.set_xscale("log")
    ax.legend()

    fig.savefig(name, dpi=fig.dpi * 2)


def plot2_time(py_data, wg_data, suffix):
    py_x = py_data["x"]
    py_ys = py_data["ys"]
    py_sizes = py_data["sizes"]

    wg_x = wg_data["x"]
    wg_ys = wg_data["ys"]
    wg_sizes = wg_data["sizes"]

    assert py_sizes == wg_sizes

    fig, ax = plt.subplots()
    for i, size in enumerate(py_sizes):
        py_d, py_k = Poly.fit(py_x, py_ys[str(size)], 1).convert().coef
        wg_d, wg_k = Poly.fit(wg_x, wg_ys[str(size)], 1).convert().coef

        xhat = np.logspace(3, 5)
        py_yhat = xhat * py_k + py_d
        wg_yhat = xhat * wg_k + wg_d

        ax.plot(py_x, py_ys[str(size)], "o", color=COLORS[i], alpha=0.3, label="Python asyncio")
        ax.plot(xhat, py_yhat, "-", color=COLORS[i])

        ax.plot(wg_x, wg_ys[str(size)], "o", color=COLORS[len(COLORS) - i - 1], alpha=0.3, label="mitmproxy_wireguard")
        ax.plot(xhat, wg_yhat, "-", color=COLORS[len(COLORS) - i - 1])

    ax.set_title("Echo server runtime comparison")

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Execution time /s")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.legend()

    fig.savefig(f"comp_data_{suffix}.png", dpi=fig.dpi * 2)


def plot2_throughput(py_data, wg_data, suffix):
    py_x = py_data["x"]
    py_ys = py_data["ys"]
    py_sizes = py_data["sizes"]

    wg_x = wg_data["x"]
    wg_ys = wg_data["ys"]
    wg_sizes = wg_data["sizes"]

    assert py_sizes == wg_sizes

    fig, ax = plt.subplots()
    for i, size in enumerate(py_sizes):
        py_y = np.array(py_ys[str(size)])
        wg_y = np.array(wg_ys[str(size)])

        py_d, py_k = Poly.fit(py_x, py_y, 1).convert().coef
        wg_d, wg_k = Poly.fit(wg_x, wg_y, 1).convert().coef

        py_pps = py_x / py_y
        wg_pps = wg_x / wg_y

        xhat = np.logspace(3, 5)
        py_yhat = xhat / (xhat * py_k + py_d)
        wg_yhat = xhat / (xhat * wg_k + wg_d)

        ax.plot(py_x, py_pps, "o", color=COLORS[i], alpha=0.3, label="Python asyncio")
        ax.plot(xhat, py_yhat, color=COLORS[i])
        ax.hlines(xmin=1e3, xmax=1e5, y=1 / py_k, linestyles="dashed", color=COLORS[i], alpha=0.3, linewidth=2)

        ax.plot(wg_x, wg_pps, "o", color=COLORS[len(COLORS) - i - 1], alpha=0.3, label="mitmproxy_wireguard")
        ax.plot(xhat, wg_yhat, color=COLORS[len(COLORS) - i - 1])
        ax.hlines(
            xmin=1e3,
            xmax=1e5,
            y=1 / wg_k,
            linestyles="dashed",
            color=COLORS[len(COLORS) - i - 1],
            alpha=0.3,
            linewidth=2,
        )

        print("Throughput ({}, Python asyncio, average): {} ± {}".format(suffix, np.mean(py_pps), np.std(py_pps)))
        print("Throughput ({}, Python asyncio, estimated): {}".format(suffix, 1 / py_k))
        print("Startup time ({}, Python asyncio, estimated): {}".format(suffix, py_d))
        print("Throughput ({}, mitmproxy_wireguard, average): {} ± {}".format(suffix, np.mean(wg_pps), np.std(wg_pps)))
        print("Throughput ({}, mitmproxy_wireguard, estimated): {}".format(suffix, 1 / wg_k))
        print("Startup time ({}, mitmproxy_wireguard, estimated): {}".format(suffix, wg_d))

    ax.set_title("Echo server throughput comparison")

    ax.set_xlabel("Number of packets")
    ax.set_ylabel("Throughput /(packets/s)")

    ax.set_xscale("log")
    ax.legend()

    fig.savefig(f"comp_tp_{suffix}.png", dpi=fig.dpi * 2)


def main():
    for suffix in ["local", "nonlocal"]:

        with open(f"py_data_{suffix}.json") as file:
            py_data = json.load(file)

        with open(f"wg_data_{suffix}.json") as file:
            wg_data = json.load(file)

        plot_time(py_data, f"py_data_{suffix}.png", "Python asyncio")
        plot_time(wg_data, f"wg_data_{suffix}.png", "mitmproxy_wireguard")

        plot_throughput(py_data, f"py_tp_{suffix}.png", "Python asyncio")
        plot_throughput(wg_data, f"wg_tp_{suffix}.png", "mitmproxy_wireguard")

        plot2_time(py_data, wg_data, suffix)
        plot2_throughput(py_data, wg_data, suffix)


if __name__ == "__main__":
    main()
