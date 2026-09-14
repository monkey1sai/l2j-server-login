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
package com.l2jserver.loginserver.network.serverpackets;

import com.l2jserver.loginserver.SessionKey;

/**
 * Packet sent to the client to confirm that the requested server login was successful.
 * @author Zoey76
 * @version 2.6.1.0
 */
public final class PlayOk extends L2LoginServerPacket {
	private final int playOk1;
	private final int playOk2;

	public PlayOk(SessionKey sessionKey) {
		playOk1 = sessionKey.playOkID1;
		playOk2 = sessionKey.playOkID2;
	}

	@Override
	protected void write() {
		writeC(0x07);
		writeD(playOk1);
		writeD(playOk2);
	}
}
