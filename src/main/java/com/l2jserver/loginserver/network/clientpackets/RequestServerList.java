/*
 * Copyright © 2004-2026 L2J Server
 * 
 * This file is part of L2J Server.
 * 
 * L2J Server is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * L2J Server is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package com.l2jserver.loginserver.network.clientpackets;

import com.l2jserver.loginserver.network.serverpackets.LoginFail.LoginFailReason;
import com.l2jserver.loginserver.network.serverpackets.ServerList;

/**
 * Request for the server list packet.
 *
 * <pre>
 * Format: ddc
 * d: fist part of session id
 * d: second part of session id
 * c: ?
 * </pre>
 * 
 * @version 2.6.1.0
 */
public class RequestServerList extends L2LoginClientPacket {
	private int sessionKey1;
	private int sessionKey2;
	private int data3;

	public int getSessionKey1() {
		return sessionKey1;
	}

	public int getSessionKey2() {
		return sessionKey2;
	}

	public int getData3() {
		return data3;
	}

	@Override
	public boolean readImpl() {
		if (super._buf.remaining() >= 8) {
			sessionKey1 = readD(); // loginOk 1
			sessionKey2 = readD(); // loginOk 2
			return true;
		}
		return false;
	}

	@Override
	public void run() {
		if (getClient().getSessionKey().checkLoginPair(sessionKey1, sessionKey2)) {
			getClient().sendPacket(new ServerList(getClient()));
		} else {
			getClient().close(LoginFailReason.REASON_ACCESS_FAILED);
		}
	}
}
