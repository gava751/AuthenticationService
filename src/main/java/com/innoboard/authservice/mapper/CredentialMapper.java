package com.innoboard.authservice.mapper;

import com.innoboard.authservice.domain.Credential;
import com.innoboard.authservice.dto.CredentialResponse;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface CredentialMapper {

    CredentialResponse toResponse(Credential entity);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "userId", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "active", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(source = "login", target = "username")
    Credential toEntity(RegisterCredentialsRequest request);
}
