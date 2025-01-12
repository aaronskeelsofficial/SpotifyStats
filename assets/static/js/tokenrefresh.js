let date = new Date();
date.setTime(date.getTime() + (1000*60*20));
Cookies.set("token", Cookies.get("token"), { expires: date, sameSite: "Lax" });