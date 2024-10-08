package com.son.spring.jwt.mongodb.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

public interface GetFilesByUserId {
//	@Builder
//	@Data
//	@AllArgsConstructor
//	@NoArgsConstructor
//	class Request {
//		private String userId;
//	}

	@Builder
	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	class Response {
		List<FileInfoDTO> fileInfos;
	}

	@Builder
	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	class FileInfoDTO {
		private String id;
		private String fileName;
		private LocalDateTime createdAt;
	}
}
