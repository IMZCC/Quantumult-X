module.exports.parse = (raw, { yaml }) => {
	const rawObj = yaml.parse(raw)
	const { 'Rule': rules = [], 'Proxy Group':groups = []} = rawObj

	//清除订阅自带策略
	delete rawObj['Rule']
	delete rawObj['Proxy Group']

	//临时保存
	// var temp ="";
	//保存节点信息
	var node = [];
//--------------------------------------------------变量节点-----------------------------------------------------
	for(var i =0;i < rawObj['proxies'].length;i++){
		node[i]=rawObj['proxies'][i]["name"];
	}

//--------------------------------------------------策略组-----------------------------------------------------
	//节点选择
	groups.push({
		"name":"节点选择",
		"type": "select",
		"proxies":["自动选择","DIRECT"].concat(node)
	})
	//自动选择
	groups.push({
		"name":"自动选择",
		"type": "url-test",
		"url": "http://www.gstatic.com/generate_204",
		"interval": 300,
		"tolerance": 50,
		"proxies":node
	})
	//国外媒体
	groups.push({
		"name":"国外媒体",
		"type": "select",
		"proxies":["节点选择","自动选择","全球直连"].concat(node)
	})
	//Telegram
	groups.push({
		"name":"Telegram",
		"type": "select",
		"proxies":["节点选择","全球直连"].concat(node)
	})
	//Microsoft
	groups.push({
		"name":"Microsoft",
		"type": "select",
		"proxies":["全球直连","节点选择"].concat(node)
	})
	//Apple
	groups.push({
		"name":"Apple",
		"type": "select",
		"proxies":["节点选择","全球直连"].concat(node)
	})
	//谷歌服务
	groups.push({
		"name":"Google",
		"type": "select",
		"proxies":["节点选择","全球直连","自动选择"].concat(node)
	})
	groups.push({
		"name":"Github",
		"type": "select",
		"proxies":["节点选择","全球直连","自动选择"].concat(node)
	})
	//全球直连
	groups.push({
		"name":"全球直连",
		"type": "select",
		"proxies":["DIRECT","节点选择","自动选择"]
	})
	// 全球拦截
	groups.push({
		"name":"全球拦截",
		"type": "select",
		"proxies":["REJECT","DIRECT"]
	})
	//应用净化
	groups.push({
		"name":"AD",
		"type": "select",
		"proxies":["REJECT","DIRECT"]
	})
	//手动添加的策略
	groups.push({
		"name":"黑白名单",
		"type": "select",
		"proxies":["节点选择","全球直连","自动选择"].concat(node)
	})

//--------------------------------------------------规则-----------------------------------------------------
	rules.unshift(
		"PROCESS-NAME,v2ray,DIRECT",
		"PROCESS-NAME,xray,DIRECT",
		"PROCESS-NAME,naive,DIRECT",
		"PROCESS-NAME,trojan,DIRECT",
		"PROCESS-NAME,trojan-go,DIRECT",
		"PROCESS-NAME,ss-local,DIRECT",
		"PROCESS-NAME,privoxy,DIRECT",
		"PROCESS-NAME,leaf,DIRECT",
		"PROCESS-NAME,v2ray.exe,DIRECT",
		"PROCESS-NAME,xray.exe,DIRECT",
		"PROCESS-NAME,naive.exe,DIRECT",
		"PROCESS-NAME,trojan.exe,DIRECT",
		"PROCESS-NAME,trojan-go.exe,DIRECT",
		"PROCESS-NAME,ss-local.exe,DIRECT",
		"PROCESS-NAME,privoxy.exe,DIRECT",
		"PROCESS-NAME,leaf.exe,DIRECT",
		"PROCESS-NAME,Surge,DIRECT",
		"PROCESS-NAME,Surge 2,DIRECT",
		"PROCESS-NAME,Surge 3,DIRECT",
		"PROCESS-NAME,Surge 4,DIRECT",
		"PROCESS-NAME,Surge%202,DIRECT",
		"PROCESS-NAME,Surge%203,DIRECT",
		"PROCESS-NAME,Surge%204,DIRECT",
		"PROCESS-NAME,Thunder,DIRECT",
		"PROCESS-NAME,DownloadService,DIRECT",
		"PROCESS-NAME,qBittorrent,DIRECT",
		"PROCESS-NAME,Transmission,DIRECT",
		"PROCESS-NAME,fdm,DIRECT",
		"PROCESS-NAME,aria2c,DIRECT",
		"PROCESS-NAME,Folx,DIRECT",
		"PROCESS-NAME,NetTransport,DIRECT",
		"PROCESS-NAME,uTorrent,DIRECT",
		"PROCESS-NAME,WebTorrent,DIRECT",
		"PROCESS-NAME,aria2c.exe,DIRECT",
		"PROCESS-NAME,BitComet.exe,DIRECT",
		"PROCESS-NAME,fdm.exe,DIRECT",
		"PROCESS-NAME,NetTransport.exe,DIRECT",
		"PROCESS-NAME,qbittorrent.exe,DIRECT",
		"PROCESS-NAME,Thunder.exe,DIRECT",
		"PROCESS-NAME,ThunderVIP.exe,DIRECT",
		"PROCESS-NAME,transmission-daemon.exe,DIRECT",
		"PROCESS-NAME,transmission-qt.exe,DIRECT",
		"PROCESS-NAME,uTorrent.exe,DIRECT",
		"PROCESS-NAME,WebTorrent.exe,DIRECT",
		"DOMAIN,mojie.pw,节点选择",
		"DOMAIN-KEYWORD,clash,节点选择",
		"DOMAIN-KEYWORD,mojie,节点选择",
		"RULE-SET,private,DIRECT",
		"RULE-SET,direct,全球直连",
		"RULE-SET,icloud,Apple",
		"RULE-SET,apple,Apple",
		"RULE-SET,google,Google",
		"RULE-SET,reject,全球拦截",
		"RULE-SET,proxy,节点选择",
		"RULE-SET,telegramcidr,Telegram",
		"DOMAIN-KEYWORD,clash,节点选择",

		"MATCH,DIRECT")
//--------------------------------------------------规则集-----------------------------------------------------
	var rule_providers=`rule-providers:
    reject:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt
      path: ./ruleset/reject.yaml
      interval: 86400
    icloud:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt
      path: ./ruleset/icloud.yaml
      interval: 86400
    apple:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt
      path: ./ruleset/apple.yaml
      interval: 86400
    google:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/LM-Firefly/Rules@master/PROXY/Google.list
      path: ./ruleset/google.yaml
      interval: 86400
    proxy:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt
      path: ./ruleset/proxy.yaml
      interval: 86400
    direct:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt
      path: ./ruleset/direct.yaml
      interval: 86400
    private:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt
      path: ./ruleset/private.yaml
      interval: 86400
    gfw:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt
      path: ./ruleset/gfw.yaml
      interval: 86400
    greatfire:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt
      path: ./ruleset/greatfire.yaml
      interval: 86400
    tld-not-cn:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt
      path: ./ruleset/tld-not-cn.yaml
      interval: 86400
    github:
      type: http
      behavior: domain
      url: https://cdn.jsdelivr.net/gh/LM-Firefly/Rules@master/Clash-RuleSet-Classical/PROXY/Github.yaml
      path: ./ruleset/github.yaml
      interval: 86400
    telegramcidr:
      type: http
      behavior: ipcidr
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt
      path: ./ruleset/telegramcidr.yaml
      interval: 86400
    cncidr:
      type: http
      behavior: ipcidr
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt
      path: ./ruleset/cncidr.yaml
      interval: 86400
    lancidr:
      type: http
      behavior: ipcidr
      url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt
      path: ./ruleset/lancidr.yaml
      interval: 86400`

	// rawObj['rule-providers']=rule_providers

	//修改模式为规则模式
	rawObj['mode'] = 'Rule'

	return yaml.stringify({ ...rawObj,'proxy-groups': groups, rules})+rule_providers
  }