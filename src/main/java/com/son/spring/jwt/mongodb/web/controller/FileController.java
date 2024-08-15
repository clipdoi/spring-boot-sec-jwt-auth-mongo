package com.son.spring.jwt.mongodb.web.controller;

import com.son.spring.jwt.mongodb.web.dto.*;
import com.son.spring.jwt.mongodb.web.service.FileService;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@PreAuthorize("hasRole('ADMIN')")
@RestController
@AllArgsConstructor
public class FileController {

	private final FileService fileService;

	@GetMapping("/api/user/saveFile")
	public SaveFileDto.Response saveFile(@RequestPart("file") MultipartFile file, @RequestParam String userId) throws IOException {
		return fileService.saveFile(file, userId);
	}

	@PostMapping("/api/user/saveFile")
	public SaveFileDto.Response saveFilePost(@RequestPart("file") MultipartFile file, @RequestParam String userId) throws IOException {
		return fileService.saveFile(file, userId);
	}

	@PostMapping("/api/user/saveFileData")
	SaveFileDto.Response saveFileData(@RequestBody SaveFileDto.Request request) {
		return fileService.saveFile(request);
	}

	@GetMapping("/api/user/getFilesByUserId")
	public GetFilesByUserId.Response getFilesByUserId(@RequestParam String userName) {
		return fileService.getFilesByUserName(userName);
	}

	@GetMapping("/api/user/getFileById")
	public GetFileById.Response getFileById(@RequestParam String userName, @RequestParam String fileId) {
		return fileService.getFileById(userName, fileId);
	}

	@PostMapping("/api/user/updateFileById")
	public UpdateFileByIdDto.Response updateFileById(@RequestBody UpdateFileByIdDto.Request request) {
		return fileService.updateFileById(request);
	}

	@GetMapping("/api/user/logs")
	public GetLogUserDto.Response getLogUsers(@RequestParam String userName) {
		return fileService.getLogsUser(userName);
	}

	@GetMapping("/api/user/activity")
	public GetActivityFile.Response getActivityFile(@RequestParam String userName) {
		return fileService.getActivityFile(userName);
	}
}
