<?php

namespace kjBot\Driver\OneBot;

use BotMan\BotMan\Users\User;
use BotMan\BotMan\Drivers\HttpDriver;
use BotMan\BotMan\Interfaces\WebAccess;
use Tightenco\Collect\Support\Collection;
use BotMan\BotMan\Messages\Incoming\Answer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\ParameterBag;
use BotMan\BotMan\Messages\Incoming\IncomingMessage;
use BotMan\BotMan\Messages\Outgoing\OutgoingMessage;

class OneBotDriver extends HttpDriver{

    const DRIVER_NAME = 'OneBot';
    const PRIVATE_REPLY = 0;
    const GROUP_REPLY = 1;

    /**
     * @param Request $request
     */
    public function buildPayload(Request $request){
        $this->payload = new ParameterBag((array) json_decode($request->getContent()), true);
        $this->event = Collection::make((array) $this->payload->all());
        $this->signature = $request->headers->get('X-Signature', '');
        $this->content = $request->getContent();
        $this->config = Collection::make($this->config->get('onebot', []));
    }

    /**
     * 验证请求是否有效(hmac sha1)
     *
     * @return bool
     */
    protected function verifyRequest($content): bool{
        $secret = $this->config->get('secret');
        if(is_null($secret)) return true; //如果未设定secret则认证通过

        $sig = hash_hmac('sha1', $content, $secret);
        return $this->signature === ('sha1='.$sig);
    }

    /**
     * 确定请求是否是发给该驱动(即OneBot)
     *
     * @return bool
     */
    public function matchesRequest(){
        return (!is_null($this->event->get('time')))
            && (!is_null($this->event->get('self_id')))
            && (!is_null($this->event->get('post_type')))
            && $this->verifyRequest($this->content)
        ;
    }

    /**
     * 确定驱动基本配置是否完整
     * 
     * @return bool
     */
    public function isConfigured(): bool{
        return !empty($this->config->get('endpoint'));
    }

    /**
     * 将数据转化为收到的消息(IncomingMessage)
     *
     * @return array
     */
    public function getMessages()
    {
        if(empty($this->messages)){
            $message = $this->event->get('message');
            $userId = $this->event->get('user_id');
            $groupId = $this->event->get('group_id');
            $this->messages = [new IncomingMessage($message, $userId, $groupId, $this->payload)];
        }
        return $this->messages;
    }

    /**
     * 返回消息中的用户
     * @param IncomingMessage $matchingMessage
     * @return UserInterface
     */
    public function getUser(IncomingMessage $matchingMessage){
        return new User($matchingMessage->getSender());
    }

    /**
     * @param IncomingMessage $message
     * @return \BotMan\BotMan\Messages\Incoming\Answer
     */
    public function getConversationAnswer(IncomingMessage $message){
        return Answer::create($message->getText())->setMessage($message);
    }

    /**
     * 将待发送消息(OutgoingMessage)转化为要发送的载荷(payload)
     * 
     * @param string|Question|OutgoingMessage $message
     * @param IncomingMessage $matchingMessage
     * @param array $additionalParameters
     * @return Response
     */
    public function buildServicePayload($message, $matchingMessage, $additionalParameters = [])
    {
        if (! $message instanceof WebAccess && ! $message instanceof OutgoingMessage) {
            $this->errorMessage = 'Unsupported message type.';
            $this->replyStatusCode = 500;
        }

        if($additionalParameters['sendType'] === static::GROUP_REPLY){ //强制群聊
            $target = [
                'message_type' => 'group',
                'group_id' => $matchingMessage->getSender(),
            ];
        }else if($additionalParameters['sendType'] === static::PRIVATE_REPLY){ //强制私聊
            $target = [
                'message_type' => 'private',
                'user_id' => $matchingMessage->getSender(),
            ];
        }else if(is_null($matchingMessage->getRecipient())){ //如果无Recipient（即私聊）
            $target = [
                'message_type' => 'private',
                'user_id' => $matchingMessage->getSender(),
            ];
        }else if($matchingMessage->getRecipient() === ''){ //如果是拟态消息（即->say()）
            //do nothing
        }else{ //否则为群聊（？）
            $target = [
                'message_type' => 'group',
                'group_id' => $matchingMessage->getRecipient(),
            ];
        }

        return array_merge([
            'message' => $message->getText(),
        ], $target);
    }

    /**
     * @param mixed $payload
     * @return Response
     */
    public function sendPayload($payload){
        $response = $this->http->post($this->config->get('endpoint').'send_msg', [
            "access_token" => $this->config->get('token')
        ], $payload, [
            'Content-Type: application/json'
        ], true);

        return $response;
    }

    public function sendRequest($endpoint, array $parameters, IncomingMessage $matchingMessage){
        return $this->http->post($endpoint, $parameters);
    }

    /**
     * 手动请求
     *
     * @param string $type "get"/"post"
     * @param string $endpoint api名称
     * @param array<string => string> $urlParameters url参数
     * @param array<string> $headers 请求头
     * @param array $postParameters post的数据
     * @param boolean $asJson 以json方式发送
     * @return Response
     */
    public function manualRequest($type, string $endpoint, array $urlParameters = [], array $headers = [], array $postParameters = [], bool $asJson = false){
        switch($type){
            case 'get':
                return $this->http->get($this->config->get('endpoint').$endpoint, $urlParameters, $headers, $asJson);
            case 'post':
                return $this->http->post($this->config->get('endpoint').$endpoint, $urlParameters, $postParameters, $headers, $asJson);
        }
    }

}

