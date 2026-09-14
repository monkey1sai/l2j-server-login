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

import com.l2jserver.loginserver.network.L2LoginClient.LoginClientState;
import com.l2jserver.loginserver.network.serverpackets.GGAuth;
import com.l2jserver.loginserver.network.serverpackets.LoginFail.LoginFailReason;

/**
 * Handles GameGuard authentication.
 * Format: ddddd
 * @author -Wooden-
 * @version 2.6.1.0
 */
public class AuthGameGuard extends L2LoginClientPacket {
	private int sessionId;
	private int data1;
	private int data2;
	private int data3;
	private int data4;

	public int getSessionId() {
		return sessionId;
	}

	public int getData1() {
		return data1;
	}

	public int getData2() {
		return data2;
	}

	public int getData3() {
		return data3;
	}

	public int getData4() {
		return data4;
	}

	@Override
	protected boolean readImpl() {
		if (super._buf.remaining() >= 20) {
			sessionId = readD();
			data1 = readD();
			data2 = readD();
			data3 = readD();
			data4 = readD();
			return true;
		}
		return false;
	}

	@Override
	public void run() {
		if (sessionId == getClient().getSessionId()) {
			getClient().setState(LoginClientState.AUTHED_GG);
			getClient().sendPacket(new GGAuth(getClient().getSessionId()));
		} else {
			getClient().close(LoginFailReason.REASON_ACCESS_FAILED);
		}
	}
}
