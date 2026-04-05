use anyhow::{Context, Result};
use hickory_proto::{
    op::{Header, Message, MessageType, ResponseCode},
    rr::Record,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, ResponseHandler, ResponseInfo},
};

use super::DnsResolution;

impl DnsResolution {
    pub(super) fn from_answers(answers: Vec<Record>) -> Self {
        Self {
            response_code: ResponseCode::NoError,
            answers,
        }
    }

    pub(super) fn from_error(response_code: ResponseCode) -> Self {
        Self {
            response_code,
            answers: Vec::new(),
        }
    }

    pub(super) async fn send_hickory_response<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let fallback_header = Self::build_response_header(request.header(), ResponseCode::ServFail);

        let send_result = if self.response_code != ResponseCode::NoError {
            response_handle
                .send_response(builder.error_msg(request.header(), self.response_code))
                .await
        } else if self.answers.is_empty() {
            response_handle
                .send_response(builder.build_no_records(Self::build_response_header(
                    request.header(),
                    ResponseCode::NoError,
                )))
                .await
        } else {
            let empty_records: [Record; 0] = [];
            response_handle
                .send_response(builder.build(
                    Self::build_response_header(request.header(), ResponseCode::NoError),
                    self.answers.iter(),
                    empty_records.iter(),
                    empty_records.iter(),
                    empty_records.iter(),
                ))
                .await
        };

        match send_result {
            Ok(info) => info,
            Err(error) => {
                tracing::warn!(?error, src = %request.src(), "Failed to send fake DNS response");
                fallback_header.into()
            }
        }
    }

    pub(super) fn to_message_bytes(&self, request: &Message) -> Result<Vec<u8>> {
        if self.response_code != ResponseCode::NoError {
            return Self::build_error_message_bytes(request, self.response_code);
        }

        let mut response = Self::build_response_message(request);
        for answer in &self.answers {
            response.add_answer(answer.clone());
        }

        response
            .to_vec()
            .context("failed to serialize fake DNS response")
    }

    fn build_error_message_bytes(
        request: &Message,
        response_code: ResponseCode,
    ) -> Result<Vec<u8>> {
        let mut response = Self::build_response_message(request);
        response.set_response_code(response_code);
        response
            .to_vec()
            .context("failed to serialize fake DNS error response")
    }

    fn build_response_message(request: &Message) -> Message {
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code())
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for query in request.queries() {
            response.add_query(query.clone());
        }
        response
    }

    fn build_response_header(request_header: &Header, response_code: ResponseCode) -> Header {
        let mut header = request_header.clone();
        header
            .set_message_type(MessageType::Response)
            .set_recursion_available(true)
            .set_response_code(response_code);
        header
    }
}
