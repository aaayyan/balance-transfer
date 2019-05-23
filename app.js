var log4js = require('log4js');//node中输出日志的
var logger = log4js.getLogger('SampleWebApp');
var koa = require ('koa')
var koajwt = require('koa-jwt');
//var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var bodyParser = require('koa-bodyparser');//改为koa的，增加依赖包
var http = require('http');
var util = require('util');
var router=require('koa-router')();//z这里添加对url的处理
var app = new koa();
var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');//对token生成，验证，解析的过程进行修改
//var bearerToken = require('express-bearer-token');
var cors = require('cors');//node.js跨域模块，不改

require('./config.js');
var hfc = require('fabric-client');

var helper = require('./app/helper.js');
var createChannel = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var query = require('./app/query.js');
var host = process.env.HOST || hfc.getConfigSetting('host');
var port = process.env.PORT || hfc.getConfigSetting('port');
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SET CONFIGURATONS ////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//app.options('*', cors());//解决跨域问题
//app.use(cors());//解决跨域问题，不改
//support parsing of application/json type post data
app.use(bodyParser());
//support parsing of application/x-www-form-urlencoded post data
//app.use(bodyParser.urlencoded({
//	extended: false
//}));
//错误处理,验证token
app.use((ctx,next)=>{
	return next().catch((err)=>{
		if(err.status===401){
			ctx.status=401;
			ctx.body='Protected resource, use Authorization header to get access\n';
		}else{
			throw err;
		}
		
	})
})
app.use(koajwt({
	secret:'my_token'
}).unless({
	path:['/users']//指定哪些url不用进行token的验证
}))
app.use(function(ctx, next) {
	logger.debug(' ------>>>>>> new request for %s',ctx.request.originalUrl);
	if (ctx.request.originalUrl.indexOf('/users') >= 0) {
		return next();
	}

	var token = ctx.request.token;
	jwt.verify(token, app.get('secret'), function(err, decoded) {
		if (err) {
			ctx.response.send({
				success: false,
				message: 'Failed to authenticate token. Make sure to include the ' +
					'token returned from /users call in the authorization header ' +
					' as a Bearer token'
			});
			return;
		} else {
			// add the decoded user name and org name to the request object
			// for the downstream code to use
			ctx.request.username = decoded.username;
			ctx.request.orgname = decoded.orgName;
			logger.debug(util.format('Decoded from JWT token: username - %s, orgname - %s', decoded.username, decoded.orgName));
			return next();
		}
	});
});
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//这一部分不改
 var server = app.listen(port);
 logger.info('****************** SERVER STARTED ************************');
 logger.info('***************  http://%s:%s  ******************',host,port);
server.timeout = 240000;
 function getErrorMessage(field) {
 	var response = {
		success: false,
 		message: field + ' field is missing or Invalid in the request'
 	};
 	return response;
 }
///////////////////////////////////////////////////////////////////////////////
///////////////////////// REST ENDPOINTS START HERE ///////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Register and enroll user
router.post('/users',async (ctx) => {
	var username=ctx.request.body.username;
	var orgName=ctx.request.body.orgname;
	logger.debug('End point : /users');
	logger.debug('User name : ' + username);
	logger.debug('Org name  : ' + orgName);
	if(!username){
		ctx.response.json(getErrorMessage('\'username\''));
		return;
	}
	if(!orgName){
		ctx.response.json(getErrorMessage('\'orgName\''));
		return;
	}
	var token = jwt.sign({
		exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
		username: username,
		orgName: orgName
	}, app.get('secret'));
	let response = await helper.getRegisteredUser(username, orgName, true);
	logger.debug('-- returned from registering the username %s for organization %s',username,orgName);
	if (response && typeof response !== 'string') {
		logger.debug('Successfully registered the username %s for organization %s',username,orgName);
		response.token = token;
		ctx.response.json(response);
	} else {
		logger.debug('Failed to register the username %s for organization %s with::%s',username,orgName,response);
		ctx.response.json({success: false, message: response});
	}
});
// Create Channel
router.post('/channels', async function(ctx) {
	logger.info('<<<<<<<<<<<<<<<<< C R E A T E  C H A N N E L >>>>>>>>>>>>>>>>>');
	logger.debug('End point : /channels');
	var channelName = ctx.request.body.channelName;
	var channelConfigPath = ctx.request.body.channelConfigPath;
	logger.debug('Channel name : ' + channelName);
	logger.debug('channelConfigPath : ' + channelConfigPath); //../artifacts/channel/mychannel.tx
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!channelConfigPath) {
		res.json(getErrorMessage('\'channelConfigPath\''));
		return;
	}

	let message = await createChannel.createChannel(channelName, channelConfigPath, req.username, req.orgname);
	res.send(message);
});

