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
package com.l2jserver.loginserver.model;

import java.util.Objects;

/**
 * Account Info.
 * @author HorridoJoho
 * @version 2.6.1.0
 */
public final class AccountInfo {
	private final String login;
	private final String passwordHash;
	private final int accessLevel;
	private final int lastServer;

	public AccountInfo(String login, String passwordHash, int accessLevel, int lastServer) {
		Objects.requireNonNull(login, "login parameter is null");
		Objects.requireNonNull(passwordHash, "passHash parameter is null");

		if (login.isEmpty()) {
			throw new IllegalArgumentException("login string is empty");
		}
		if (passwordHash.isEmpty()) {
			throw new IllegalArgumentException("passHash string is empty");
		}

		this.login = login.toLowerCase();
		this.passwordHash = passwordHash;
		this.accessLevel = accessLevel;
		this.lastServer = lastServer;
	}

	public boolean checkPassHash(String passHash) {
		return passwordHash.equals(passHash);
	}

	public String getLogin() {
		return login;
	}

	public int getAccessLevel() {
		return accessLevel;
	}

	public int getLastServer() {
		return lastServer;
	}
}
