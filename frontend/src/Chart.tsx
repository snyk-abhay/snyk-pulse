import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart, PieChart } from "echarts/charts";
import {
  AriaComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";

echarts.use([
  BarChart,
  LineChart,
  PieChart,
  AriaComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  SVGRenderer,
]);

export function Chart({
  option,
  label,
  height = 275,
}: {
  option: EChartsCoreOption;
  label: string;
  height?: number | "fill";
}) {
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const chart = echarts.init(container.current!, undefined, {
      renderer: "svg",
    });
    const render = () => {
      const styles = getComputedStyle(container.current!);
      const token = (name: string) => styles.getPropertyValue(name).trim();
      // --text2 keeps small axis labels readable (≥4.5:1) in both themes.
      const foreground = token("--text2");
      const border = token("--border");
      // Options may use "var(--token)" colors; ECharts needs concrete values,
      // re-read on every render so a theme switch recolors the chart.
      const resolve = (value: unknown): unknown =>
        typeof value === "string"
          ? value.replace(/var\((--[\w-]+)\)/g, (_, name) => token(name) || name)
          : Array.isArray(value)
            ? value.map(resolve)
            : value && typeof value === "object"
              ? Object.fromEntries(
                  Object.entries(value).map(([k, v]) => [k, resolve(v)]),
                )
              : value;
      const resolved = resolve(option) as EChartsCoreOption;
      // Merge theme colors into each axis part so per-chart settings (e.g.
      // axisLabel.interval) don't drop the color back to ECharts' default.
      const axis = (value: unknown) => {
        if (!value) return undefined;
        const a = value as Record<string, Record<string, unknown> | undefined>;
        return {
          ...a,
          axisLabel: { color: foreground, ...a.axisLabel },
          axisLine: { ...a.axisLine, lineStyle: { color: border } },
          splitLine: { ...a.splitLine, lineStyle: { color: border } },
        };
      };
      chart.setOption(
        {
          animation: false,
          aria: { enabled: true },
          textStyle: { fontFamily: "Geist, sans-serif", color: foreground },
          ...resolved,
          xAxis: axis(resolved.xAxis),
          yAxis: axis(resolved.yAxis),
          ...(resolved.legend
            ? {
                legend: {
                  textStyle: { color: token("--text2") },
                  inactiveColor: border,
                  ...(resolved.legend as object),
                },
              }
            : {}),
          ...(resolved.tooltip
            ? {
                tooltip: {
                  backgroundColor: token("--raised") || token("--surface"),
                  borderColor: token("--border-strong"),
                  textStyle: { color: token("--text") },
                  ...(resolved.tooltip as object),
                },
              }
            : {}),
        },
        // Replace, not merge, so colors from the previous theme never linger.
        true,
      );
      chart.resize();
    };
    render();
    // The theme toggle flips data-theme on <html>; redraw with the new tokens.
    const theme = new MutationObserver(render);
    theme.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    const print = window.matchMedia("print");
    print.addEventListener("change", render);
    window.addEventListener("beforeprint", render);
    window.addEventListener("afterprint", render);
    const resize = new ResizeObserver(() => chart.resize());
    resize.observe(container.current!);
    return () => {
      theme.disconnect();
      resize.disconnect();
      print.removeEventListener("change", render);
      window.removeEventListener("beforeprint", render);
      window.removeEventListener("afterprint", render);
      chart.dispose();
    };
  }, [option]);
  return (
    <div
      ref={container}
      role="img"
      aria-label={label}
      className={height === "fill" ? "chart-fill" : undefined}
      style={height === "fill" ? { width: "100%" } : { height, width: "100%" }}
    />
  );
}
