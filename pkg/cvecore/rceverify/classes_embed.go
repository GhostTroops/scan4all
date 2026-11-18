package rceverify

import "embed"

// javaNativeFS 嵌入两阶段 payload 的已编译 class（JDK8 / class version 52）：
//   - JavaStager.class          阶段 1：取字节 -> defineClass -> 反射调用
//   - JavaCmd.class + JavaCmd$N 阶段 2：纯 Java 命令模拟器（不 spawn 进程）
//   - CmdFilter.class           阶段 1 注册到 Servlet 容器的命令入口
//
//go:embed java/classes/*.class
var javaNativeFS embed.FS
