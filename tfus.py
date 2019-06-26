#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# apt-get install python3-dev python3-pip -y
# python3 -m pip install getch requests

from time import sleep
from threading import Thread

import atexit, getch, random, re
import requests, string, sys

ERROR = "[\x1b[31m-\x1b[0m]"
SUCCESS = "[\x1b[32m+\x1b[0m]"
INPUT = "[\x1b[33m?\x1b[0m]"
INFO = "[\x1b[35m*\x1b[0m]"

class Instagram(object):
	def __init__(self, debug):
		super(Instagram, self).__init__()
		self.debug = debug

		self.email = None
		self.username = None
		self.csrf_token = None
		self.session_id = None

		self.logged_in = False
		self.bad_account = False

	def prepare_login(self):
		response = requests.get("https://www.instagram.com/accounts/login/?hl=en", headers={
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Cache-Control": "max-age=0"
		})

		if (response.status_code == 200):
			self.csrf_token = re.search("\"csrf_token\":\"(.*?)\"", response.text).group(1)

		return self.csrf_token is not None

	def login(self, username, password):
		if (not self.prepare_login()):
			print("{} Failed to fetch CSRF token".format(ERROR))
			return False

		response = requests.post("https://www.instagram.com/accounts/login/ajax/", headers={
			"Accept": "*/*",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer": "https://www.instagram.com/accounts/login/?hl=en",
			"X-CSRFToken": self.csrf_token,
			"X-Requested-With": "XMLHttpRequest"
		}, data={
			"username": username,
			"password": password
		})

		if ("\"message\"" in response.text):
			if (response.json()["message"] == "checkpoint_required"):
				print("{} Account requires some form of login verification".format(ERROR))
			else:
				print("{} {}".format(ERROR, response.json()["message"]))
		elif (response.json()["authenticated"]):
			self.logged_in = True
			self.csrf_token = response.cookies["csrftoken"]
			self.session_id = response.cookies["sessionid"]
		else:
			print("{} gay login response fucking KYS SKID XDXD".format(ERROR))

		return self.csrf_token is not None and self.session_id is not None

	def logout(self):
		return requests.post("https://www.instagram.com/accounts/logout/", headers={
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer": "https://www.instagram.com/{}/".format(self.username)
		}, cookies={
			"csrftoken": self.csrf_token,
			"sessionid": self.session_id
		}, data={
			"csrfmiddlewaretoken": self.csrf_token
		}).status_code == 200

	def consent_required(self):
		response = requests.post("https://www.instagram.com/web/consent/update_dob/", headers={
			"Accept": "*/*",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer": "https://www.instagram.com/terms/unblock/?next=/",
			"X-CSRFToken": self.csrf_token,
			"X-Requested-With": "XMLHttpRequest"
		}, cookies={
			"sessionid": self.session_id
		}, data={
			"day": "1",
			"month": "1",
			"year": "1998",
			"current_screen_key": "dob"
		})

		if ("\"status\": \"ok\"" in response.text):
			print("{} Successfully updated consent to GDPR".format(SUCCESS))
			return self.get_profile_info();

		print("{} Failed to consent to GDPR, use an IP that is not from Europe".format(ERROR))
		return False

	def get_profile_info(self):
		response = requests.get("https://www.instagram.com/accounts/edit/", headers={
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Referer": "https://www.instagram.com/accounts/login/?next=/accounts/edit/",
			"Cache-Control": "max-age=0"
		}, cookies={
			"sessionid": self.session_id
		})

		if ("/terms/unblock/" in response.url):
			return self.consent_required()
		elif ("/accounts/edit/" in response.url and response.status_code == 200):
			self.email = re.search("\"email\":\"(.*?)\"", response.text).group(1)
			self.username = re.search("\"username\":\"(.*?)\"", response.text).group(1)

		return self.email is not None and self.username is not None

	def setup_account(self):
		return requests.post("https://www.instagram.com/accounts/edit/", headers={
			"Accept": "*/*",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer": "https://www.instagram.com/accounts/edit/",
			"X-CSRFToken": self.csrf_token,
			"X-Requested-With": "XMLHttpRequest"
		}, cookies={
			"sessionid": self.session_id
		}, data={
			"gender": "3",
			"first_name": "𝐀𝕥𝕝𝕒𝕤",
			"email": self.email,
			"username": self.username
		}).status_code == 200

	def username_available(self, username):
		response = requests.get("https://www.instagram.com/{}/".format(username), headers={
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Cache-Control": "max-age=0"
		}, cookies={
			"ds_user_id": "".join(random.choice(string.digits) for _ in range(9))
		}, timeout=1)

		if (response.status_code == 429):
			self.bad_account = True

		return response.status_code == 404

	def claim_username(self, username):
		response = requests.post("https://www.instagram.com/accounts/edit/", headers={
			"Accept": "*/*",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer": "https://www.instagram.com/accounts/edit/",
			"X-CSRFToken": self.csrf_token,
			"X-Requested-With": "XMLHttpRequest"
		}, cookies={
			"sessionid": self.session_id
		}, data={
			"gender": "3",
			"first_name": "𝐀𝕥𝕝𝕒𝕤",
			"email": self.email,
			"username": username
		})

		if ("feedback_required" in response.text or response.status_code == 429):
			self.bad_account = True

		return response.status_code == 200

class Turbo(Thread):
	def __init__(self, instagram, target):
		super(Turbo, self).__init__()
		self.instagram = instagram
		self.target = target

		self.attempts = 0
		self.claimed = False
		self.missed_swap = False
		self.running = True

	def run(self):
		while (self.running):
			try:
				if (self.instagram.username_available(self.target)):
					if (self.instagram.claim_username(self.target)):
						self.claimed = True
					else:
						self.missed_swap = True
					break

				self.attempts += 1
				print("\n[\x1b[35m{}\x1b[0m] Attempt - {:,} attempts".format(i, turbo.attempts), end="\r")

				if (self.instagram.bad_account):
				   break
				
				sleep(0.230)	
			except:
				continue

		self.running = False

def input_password(prompt):
	ret_str = ""
	print(prompt, end="", flush=True)

	while (True):
		ch = getch.getch()

		if (ch == "\n"):
			break

		if (ord(ch) == 127):
			if (len(ret_str) > 0):
				ret_str = ret_str[:-1]
				print("\b \b", end="", flush=True)
		else:
			ret_str += ch
			print("*", end="", flush=True)

	print("\n", end="", flush=True)
	return ret_str

def on_exit(instagram):
	if (instagram.logged_in):
		if (instagram.logout()):
			print("{} Successfully logged out".format(SUCCESS))
		else:
			print("{} Failed to logout :/".format(ERROR))

def main():
	print("{}   𝔸𝕥𝕝𝕒𝕤 ℂ𝕝𝕒𝕚𝕞𝕖𝕣   \n".format(SUCCESS))
	instagram = Instagram(False)
	username = input("{} Username: ".format(INPUT)).strip()
	password = input_password("{} Password: ".format(INPUT))

	if (not username or not password.strip()):
		print("\n{} Invalid username and/or password".format(ERROR))
		exit(1)

	atexit.register(on_exit, instagram)
	#print("\n{} Attempting to login...".format(INFO))

	if (not instagram.login(username, password)):
		print("{} Failed to login, check your password/account".format(ERROR))
		exit(1)

	#print("{} Successfully logged in".format(SUCCESS))

	if (not instagram.get_profile_info()):
		print("{} Failed to fetch e-mail address".format(ERROR))
		exit(1)

	if (not instagram.setup_account()):
		print("{} Failed to setup account (spamblocked)".format(ERROR))
		exit(1)

	#print("{} Successfully setup account".format(SUCCESS))

	target = input("\n{} Target: ".format(INPUT)).strip().lower()
	print("{}     Atlas Claimer v1 \n".format(SUCCESS))
	input("{} Press Enter To Start!".format(SUCCESS))
	print("\x1b[A                                      \x1b[A")

	turbo = Turbo(instagram, target)
	turbo.setDaemon(True)
	turbo.start()

	while (turbo.running):
		try:
			for i in ["|", "/", "-", "\\", "|", "/", "-", "\\"]:
				print("[\x1b[35m{}\x1b[0m] Attempt - {:,} ".format(i, turbo.attempts), end="\r", flush=True)
				sleep(0.01) # Update attempts every 100ms
		except KeyboardInterrupt:
			print("\r{} Turbo stopped, exiting after {:,} attempts...\n".format(ERROR, turbo.attempts))
			break

	if (instagram.bad_account):
		print("\r{} Bad account - Rate limited or spam blocked ({:,} attempts)\n".format(ERROR, turbo.attempts))
	elif (turbo.claimed):
		print("\r{} Claimed username @{} after {:,} attempts\n".format(SUCCESS, target, turbo.attempts + 1))
	elif (turbo.missed_swap):
		print("\r{} Missed username swap on @{} ({:,} attempts)\n".format(ERROR, target, turbo.attempts + 1))

if (__name__ == "__main__"):
	main()
