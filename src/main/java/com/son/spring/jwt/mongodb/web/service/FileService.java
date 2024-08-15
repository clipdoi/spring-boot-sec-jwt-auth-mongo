package com.son.spring.jwt.mongodb.web.service;

import com.son.spring.jwt.mongodb.web.dto.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface FileService {
	SaveFileDto.Response saveFile(MultipartFile file, String userId) throws IOException;

	GetFilesByUserId.Response getFilesByUserName(String userId);

	GetFileById.Response getFileById(String userName, String fileId);

	UpdateFileByIdDto.Response updateFileById(UpdateFileByIdDto.Request request);

	GetLogUserDto.Response getLogsUser(String userName);

	GetActivityFile.Response getActivityFile(String userName);

	SaveFileDto.Response saveFile(SaveFileDto.Request request);
}
