// SPDX-License-Identifier: MIT
// MTK BROM WebUSB 驱动
// 基于 mtkclient (Library/mtk_preloader.py, Library/Port.py, Library/Connection/usblib.py) 移植
// (c) 移植自 B.Kerler 的 mtkclient GPLv3 项目

(function(root, factory) {
	if (typeof define === 'function' && define.amd) {
		define([], factory);
	} else if (typeof exports === 'object') {
		module.exports = factory();
	} else {
		root.Mtk = factory();
	}
}(this, function() {
	'use strict';

	let Mtk = {};

	Mtk.Opt = {};
	Mtk.Opt.debug = false;

	// MediaTek USB 标识 (来自 config/usb_ids.py)
	Mtk.USB = {
		VID_MTK: 0x0E8D,
		PID_BROM: 0x0003,                       // BROM 模式
		PID_PRELOADER: [0x2000, 0x2001, 0x20FF, 0x3000, 0x6000], // Preloader 模式
	};

	// Sony 等 BROM 兼容 PID (来自 Port.py run_handshake)
	Mtk.BROM_PIDS = [0x0003, 0xF200, 0xD1E9, 0xD1E2, 0xD1EC, 0xD1DD];

	// BROM 命令字 (来自 mtk_preloader.py Cmd 枚举)
	Mtk.Cmd = {
		GET_HW_CODE:        0xFD,
		GET_BL_VER:         0xFE,
		GET_VERSION:        0xFF,
		GET_HW_SW_VER:      0xFC,
		GET_TARGET_CONFIG:  0xD8,
		GET_ME_ID:          0xE1,
		GET_SOC_ID:         0xE7,
		GET_PL_CAP:         0xFB,
		READ16:             0xD0,
		READ32:             0xD1,
		WRITE16:            0xD2,
		WRITE32:            0xD4,
		JUMP_DA:            0xD5,
		JUMP_DA64:          0xDE,
		SEND_DA:            0xD7,
	};

	function db() {
		return Mtk.Opt.debug ? console.log.bind(console, '[Mtk]') : function() {};
	}
	let log = db();

	function toHex(buffer) {
		return Array.from(new Uint8Array(buffer))
			.map(b => b.toString(16).padStart(2, '0'))
			.join(' ');
	}

	// ===================================================================
	// WebUSB 传输层 (对应 mtkclient Library/Connection/usblib.py)
	// ===================================================================
	Mtk.WebUSB = {};

	Mtk.WebUSB.Transport = function(device) {
		this.device = device;
		this.epOut = null;
		this.epIn = null;
		this.interfaceNumber = null;
	};

	// 请求用户选择 MTK 设备 (对应 UsbClass.connect 的设备发现)
	Mtk.WebUSB.Transport.open = function() {
		if (!navigator.usb) {
			return Promise.reject(new Error('当前浏览器不支持 WebUSB，请使用 Chrome/Edge 等 Chromium 内核浏览器'));
		}

		let filters = [
			{ vendorId: Mtk.USB.VID_MTK, productId: Mtk.USB.PID_BROM },
		];
		Mtk.USB.PID_PRELOADER.forEach(pid =>
			filters.push({ vendorId: Mtk.USB.VID_MTK, productId: pid }));

		return navigator.usb.requestDevice({ filters: filters })
			.then(device => device.open().then(() => device))
			.then(device => {
				let t = new Mtk.WebUSB.Transport(device);
				return t.setupInterface();
			});
	};

	// 查找 CDC Data 接口与 bulk 端点 (对应 usblib.py connect 中 interface/endpoint 查找)
	Mtk.WebUSB.Transport.prototype.setupInterface = function() {
		let device = this.device;
		if (!device.configurations || device.configurations.length === 0) {
			return Promise.reject(new Error('设备未提供 USB 配置'));
		}
		let configuration = device.configurations[0];

		// 优先查找 CDC Data(0x0A)，其次 CDC Control(0x02)，最后回退首个接口
		let target = null;
		for (let cls of [0x0A, 0x02]) {
			for (let intf of configuration.interfaces) {
				for (let alt of intf.alternates) {
					if (alt.interfaceClass === cls) {
						target = { intf, alt };
						break;
					}
				}
				if (target) break;
			}
			if (target) break;
		}
		if (!target) {
			let intf = configuration.interfaces[0];
			target = { intf, alt: intf.alternates[0] };
		}

		let { intf, alt } = target;
		this.interfaceNumber = intf.interfaceNumber;

		// 查找 bulk IN/OUT 端点 (对应 usb.util.find_descriptor)
		for (let ep of alt.endpoints) {
			if (ep.type === 'bulk') {
				if (ep.direction === 'out' && !this.epOut) this.epOut = ep;
				else if (ep.direction === 'in' && !this.epIn) this.epIn = ep;
			}
		}
		if (!this.epOut || !this.epIn) {
			return Promise.reject(new Error('未找到 bulk IN/OUT 端点，可能不是 BROM 设备'));
		}

		let cfgValue = configuration.configurationValue;
		return device.selectConfiguration(cfgValue)
			.then(() => device.claimInterface(this.interfaceNumber))
			.then(() => this.setLineCoding(921600))
			.then(() => this.setControlLineState(true))
			.then(() => {
				log('接口 ' + this.interfaceNumber +
					' EP_OUT=' + this.epOut.endpointNumber +
					' EP_IN=' + this.epIn.endpointNumber);
				return this;
			});
	};

	// SET_LINE_CODING (对应 CdcCmds.SET_LINE_CODING / set_line_coding)
	Mtk.WebUSB.Transport.prototype.setLineCoding = function(baudrate) {
		let data = new ArrayBuffer(7);
		let dv = new DataView(data);
		dv.setUint32(0, baudrate, true); // 波特率 小端
		dv.setUint8(4, 0);               // 停止位
		dv.setUint8(5, 0);               // 校验
		dv.setUint8(6, 8);               // 数据位
		return this.device.controlTransferOut({
			requestType: 'class',
			recipient: 'interface',
			request: 0x20,
			value: 0x00,
			index: this.interfaceNumber,
		}, data).catch(err => log('setLineCoding 失败:', err));
	};

	// SET_CONTROL_LINE_STATE (对应 setcontrollinestate)
	Mtk.WebUSB.Transport.prototype.setControlLineState = function(rts) {
		let ctrlstate = rts ? 2 : 0;
		return this.device.controlTransferOut({
			requestType: 'class',
			recipient: 'interface',
			request: 0x22,
			value: ctrlstate,
			index: this.interfaceNumber,
		}).catch(err => log('setControlLineState 失败:', err));
	};

	Mtk.WebUSB.Transport.prototype.send = function(buffer) {
		if (Mtk.Opt.debug) log('TX:', toHex(buffer));
		return this.device.transferOut(this.epOut.endpointNumber, buffer)
			.then(res => {
				if (res.status !== 'ok') throw new Error('transferOut 状态异常: ' + res.status);
				return res.bytesWritten;
			});
	};

	Mtk.WebUSB.Transport.prototype.receive = function(length) {
		return this.device.transferIn(this.epIn.endpointNumber, length)
			.then(res => {
				if (res.status !== 'ok') throw new Error('transferIn 状态异常: ' + res.status);
				if (Mtk.Opt.debug) log('RX:', toHex(res.data.buffer));
				return res.data.buffer;
			});
	};

	// 带超时的读取 (BROM 窗口期短，避免握手时无限挂起)
	Mtk.WebUSB.Transport.prototype.receiveTimeout = function(length, ms) {
		return Promise.race([
			this.receive(length),
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error('读取超时 (' + ms + 'ms)')), ms)),
		]);
	};

	Mtk.WebUSB.Transport.prototype.close = function() {
		return this.device.close();
	};

	// ===================================================================
	// BROM 协议客户端 (对应 mtkclient Library/mtk_preloader.py Preloader)
	// ===================================================================
	Mtk.Client = function(transport) {
		this.transport = transport;
	};

	Mtk.Client.prototype.usbwrite = function(data) {
		let buf = (data instanceof ArrayBuffer) ? data : new Uint8Array(data).buffer;
		return this.transport.send(buf);
	};

	Mtk.Client.prototype.usbread = function(length) {
		return this.transport.receive(length).then(buf => new Uint8Array(buf));
	};

	// echo: 写入后读取相同长度并校验 (对应 Port.py echo)
	Mtk.Client.prototype.echo = async function(data) {
		if (typeof data === 'number') data = [data];
		let arr = (data instanceof Uint8Array) ? Array.from(data) : data;
		await this.usbwrite(arr);
		let tmp = await this.usbread(arr.length);
		for (let i = 0; i < arr.length; i++) {
			if (tmp[i] !== (arr[i] & 0xFF)) return false;
		}
		return true;
	};

	// 读 16 位 (对应 devicehandler.py rword, 默认大端)
	Mtk.Client.prototype.rword = async function(count, little) {
		count = count || 1;
		let buf = await this.usbread(2 * count);
		let result = [];
		for (let i = 0; i < count; i++) {
			if (little) result.push(buf[i * 2] | (buf[i * 2 + 1] << 8));
			else result.push((buf[i * 2] << 8) | buf[i * 2 + 1]);
		}
		return count === 1 ? result[0] : result;
	};

	// 读 32 位 (对应 devicehandler.py rdword, 默认大端)
	Mtk.Client.prototype.rdword = async function(count, little) {
		count = count || 1;
		let buf = await this.usbread(4 * count);
		let result = [];
		for (let i = 0; i < count; i++) {
			let v;
			if (little) {
				v = buf[i * 4] | (buf[i * 4 + 1] << 8) | (buf[i * 4 + 2] << 16) | (buf[i * 4 + 3] << 24);
			} else {
				v = (buf[i * 4] << 24) | (buf[i * 4 + 1] << 16) | (buf[i * 4 + 2] << 8) | buf[i * 4 + 3];
			}
			result.push(v >>> 0);
		}
		return count === 1 ? result[0] : result;
	};

	Mtk.Client.prototype.rbyte = async function(count) {
		count = count || 1;
		return this.usbread(count);
	};

	// 握手: 发送 0xA0 0x0A 0x50 0x05，期望回显按位取反 (对应 Port.py run_handshake)
	// BROM 仅在连接后短暂活跃，故每字节带超时并重试
	Mtk.Client.prototype.handshake = async function(retries, perByteMs) {
		retries = retries || 10;
		perByteMs = perByteMs || 600;
		let startcmd = [0xA0, 0x0A, 0x50, 0x05];
		let pid = this.transport.device.productId;

		// 非 BROM PID 需先单独发送 0xA0 (来自 Port.py run_handshake)
		if (Mtk.BROM_PIDS.indexOf(pid) === -1) {
			try { await this.usbwrite([0xA0]); } catch (_) {}
		}

		for (let attempt = 0; attempt < retries; attempt++) {
			try {
				let ok = true;
				for (let byte of startcmd) {
					await this.usbwrite([byte]);
					let echo = await this.transport.receiveTimeout(1, perByteMs)
						.then(buf => new Uint8Array(buf));
					let expected = (~byte) & 0xFF;
					if (echo.length !== 1 || echo[0] !== expected) {
						ok = false;
						break;
					}
				}
				if (ok) return true;
			} catch (e) {
				log('握手第 ' + (attempt + 1) + ' 次失败:', e.message || e);
			}
			// 清空缓冲区后重试
			try { await this.transport.receiveTimeout(64, 80); } catch (_) {}
		}
		return false;
	};

	// GET_HW_CODE (0xFD): echo 后读 4 字节大端 -> (hwcode, hwver)
	Mtk.Client.prototype.getHwCode = async function() {
		if (!await this.echo(Mtk.Cmd.GET_HW_CODE)) return null;
		let val = await this.rdword();
		return {
			hwcode: (val >> 16) & 0xFFFF,
			hwver: val & 0xFFFF,
		};
	};

	// GET_BL_VER (0xFE): 写命令读 1 字节；若回显 0xFE 则处于 BROM
	Mtk.Client.prototype.getBlVer = async function() {
		await this.usbwrite([Mtk.Cmd.GET_BL_VER]);
		let res = await this.usbread(1);
		return {
			blver: res[0],
			isBrom: (res[0] === Mtk.Cmd.GET_BL_VER),
		};
	};

	// GET_VERSION (0xFF): 写命令读 1 字节 BROM 版本
	Mtk.Client.prototype.getBromVer = async function() {
		await this.usbwrite([Mtk.Cmd.GET_VERSION]);
		let res = await this.usbread(1);
		return res[0];
	};

	// GET_HW_SW_VER (0xFC): echo 后读 8 字节大端 -> 4 个 16 位
	Mtk.Client.prototype.getHwSwVer = async function() {
		if (!await this.echo(Mtk.Cmd.GET_HW_SW_VER)) return null;
		let buf = await this.usbread(8);
		return {
			hwSubCode: (buf[0] << 8) | buf[1],
			hwver: (buf[2] << 8) | buf[3],
			swver: (buf[4] << 8) | buf[5],
			fwver: (buf[6] << 8) | buf[7],
		};
	};

	// GET_TARGET_CONFIG (0xD8): echo 后读 6 字节 -> 4 字节配置 + 2 字节状态
	Mtk.Client.prototype.getTargetConfig = async function() {
		if (!await this.echo(Mtk.Cmd.GET_TARGET_CONFIG)) return null;
		let buf = await this.rbyte(6);
		let targetConfig = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
		let status = (buf[4] << 8) | buf[5];
		return {
			raw: targetConfig,
			status: status,
			sbc: !!(targetConfig & 0x1),
			sla: !!(targetConfig & 0x2),
			daa: !!(targetConfig & 0x4),
			swjtag: !!(targetConfig & 0x6),
			epp: !!(targetConfig & 0x8),
			cert: !!(targetConfig & 0x10),
			memread: !!(targetConfig & 0x20),
			memwrite: !!(targetConfig & 0x40),
			cmdC8: !!(targetConfig & 0x80),
		};
	};

	// 连接编排: 握手 + 读取全部设备信息 (对应 Preloader.init)
	Mtk.Client.prototype.connect = async function() {
		let info = {};

		let hs = await this.handshake();
		if (!hs) {
			throw new Error('握手失败，请确认设备已进入 BROM 模式（关机后按住音量键插入 USB）');
		}
		info.handshake = true;
		info.vid = this.transport.device.vendorId;
		info.pid = this.transport.device.productId;

		let hw = await this.getHwCode();
		if (!hw) throw new Error('读取 HW Code 失败');
		info.hwcode = hw.hwcode;
		info.hwver = hw.hwver;

		let bl = await this.getBlVer();
		info.blver = bl.blver;
		info.isBrom = bl.isBrom;

		try { info.bromver = await this.getBromVer(); }
		catch (e) { log('getBromVer 失败:', e); }

		try {
			let v = await this.getHwSwVer();
			if (v) Object.assign(info, v);
		} catch (e) { log('getHwSwVer 失败:', e); }

		try {
			let tc = await this.getTargetConfig();
			if (tc) info.targetConfig = tc;
		} catch (e) { log('getTargetConfig 失败:', e); }

		return info;
	};

	Mtk.Client.prototype.close = function() {
		return this.transport.close();
	};

	return Mtk;
}));
