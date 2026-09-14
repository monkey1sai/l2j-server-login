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
package com.l2jserver.loginserver.network.gameserverpackets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.commons.database.ConnectionFactory;
import com.l2jserver.commons.network.BaseRecievePacket;
import com.l2jserver.loginserver.LoginController;

/**
 * Request Temp Ban packet.
 * @author mrTJO
 * @version 2.6.1.0
 */
public class RequestTempBan extends BaseRecievePacket {

	private static final Logger LOG = LoggerFactory.getLogger(RequestTempBan.class);

	private final String accountName;

	@SuppressWarnings("unused")
	private String banReason;

	private final String ip;

	private final long banTime;

	public RequestTempBan(byte[] decrypt) {
		super(decrypt);
		accountName = readS();
		ip = readS();
		banTime = readQ();
		boolean haveReason = readC() != 0;
		if (haveReason) {
			banReason = readS();
		}
		banUser();
	}

	private void banUser() {
		// TODO(Zoey76): This must use a transaction to ensure a consistent database state.
		// TODO(Zoey76): A ban-specific table should be created to store ban reason and IP.
		try (var con = ConnectionFactory.getInstance().getConnection();
			var ps = con.prepareStatement("INSERT INTO account_data VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value=?")) {
			ps.setString(1, accountName);
			ps.setString(2, "ban_temp");
			ps.setString(3, Long.toString(banTime));
			ps.setString(4, Long.toString(banTime));
			ps.execute();
			LoginController.getInstance().addBanForAddress(ip, banTime);
		} catch (Exception ex) {
			LOG.warn("There has been an error banning account {}!", accountName, ex);
		}
	}
}
