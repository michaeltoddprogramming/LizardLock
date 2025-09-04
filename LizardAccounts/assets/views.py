from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, Http404
from django.core.files.base import ContentFile
from django.db import transaction
import hashlib
import mimetypes

from ..models import ImageAsset, DocumentAsset, ConfidentialAsset
from ..utils import (
    FERNET, ACCESS_MATRIX, check_access, is_mfa_verified,
    validate_file, sanitize_filename, log_asset_access,
    require_mfa_for_sensitive_actions, validate_file_signature
)


def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    elif size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} Kb"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.1f} Mb"
    else:
        return f"{size_bytes/(1024**3):.1f} GB"


@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def images_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None}
    try:
        lizard = request.user.lizards
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
    except:
        user_permissions = {}

    if not check_access(request.user, 'images', action):
        context['error'] = 'Access denied'
        context['user_permissions'] = user_permissions
        try:
            log_asset_access(request.user, 'images', 'unknown', action, request, False, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log denied images access: {str(log_error)}")
        return render(request, 'base/forbidden.html', context)

    try:
        if action == 'list':
            images = ImageAsset.objects.all()
            context['files'] = [{
                'id': img.id,
                'name': img.name,
                'uploaded_at': img.uploaded_at,
                'size': format_file_size(img.file.size if img.file else 0),
            } for img in images]

        elif action == 'read':
            image_id = request.GET.get('id')
            if not image_id or not image_id.isdigit():
                context['error'] = 'Valid image ID required'
            else:
                return redirect('serve_image', image_id=image_id)

        elif action == 'create' and request.method == 'POST':
            if 'file' not in request.FILES:
                context['error'] = 'No file provided'
            else:
                name = request.POST.get('name', '').strip()
                if not name:
                    context['error'] = 'Name required'
                else:
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)
                    valid, error = validate_file(uploaded_file, ['image/jpeg', 'image/png', 'image/gif'])
                    if not valid:
                        context['error'] = error
                    else:
                        with transaction.atomic():
                            ImageAsset.objects.create(
                                file=uploaded_file,
                                name=name[:255]
                            )
                        try:
                            log_asset_access(request.user, 'images', name, 'create', request, True, is_mfa_verified(request, request.user)[0])
                        except Exception as log_error:
                            import logging
                            logging.error(f"Failed to log image creation: {str(log_error)}")
                        return redirect('images')

        elif action == 'write' and request.method == 'POST':
            image_id = request.POST.get('id')
            if not image_id or not image_id.isdigit() or 'file' not in request.FILES:
                context['error'] = 'Valid image ID and file required'
            else:
                try:
                    image = ImageAsset.objects.get(id=image_id)
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)

                    valid, error = validate_file(uploaded_file, ['image/jpeg', 'image/png', 'image/gif'])
                    if not valid:
                        context['error'] = error
                    else:
                        image.file = uploaded_file
                        image.save()
                        
                        try:
                            log_asset_access(request.user, 'images', image.name, 'write', request, True, is_mfa_verified(request, request.user)[0])
                        except Exception as log_error:
                            import logging
                            logging.error(f"Failed to log image update: {str(log_error)}")
                        return redirect('images')
                except ImageAsset.DoesNotExist:
                    context['error'] = 'Image not found'
                except Exception as e:
                    context['error'] = f'Error updating image: {str(e)}'
                    import logging
                    logging.error(f"Image write error: {str(e)}")

        elif action == 'delete' and request.method == 'POST':
            image_id = request.POST.get('id')
            if not image_id or not image_id.isdigit():
                context['error'] = 'Valid image ID required'
            else:
                try:
                    image = ImageAsset.objects.get(id=image_id)
                    image_name = image.name
                    if image.file:
                        try:
                            image.file.close()
                        except Exception:
                            pass
                        image.file.delete(save=False)
                    image.delete()
                    try:
                        log_asset_access(request.user, 'images', image_name, 'delete', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log image delete: {str(log_error)}")
                    return redirect('images')
                except ImageAsset.DoesNotExist:
                    context['error'] = 'Image not found'

    except Exception as e:
        context['error'] = "An error occurred."
        import logging
        logging.error(f"Images view error: {str(e)}")

    if not context.get('error'):
        images = ImageAsset.objects.all()
        context['files'] = [{
            'id': img.id,
            'name': img.name,
            'uploaded_at': img.uploaded_at,
            'size': format_file_size(img.file.size if img.file else 0)
        } for img in images]

    context['user_permissions'] = user_permissions
    return render(request, 'assets/images.html', context)


@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def documents_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None}

    try:
        lizard = request.user.lizards
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
    except:
        user_permissions = {}

    if not check_access(request.user, 'documents', action):
        context['error'] = 'Access denied'
        context['user_permissions'] = user_permissions
        try:
            log_asset_access(request.user, 'documents', 'unknown', action, request, False, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log denied documents access: {str(log_error)}")
        return render(request, 'base/forbidden.html', context)

    try:
        if action == 'list':
            documents = DocumentAsset.objects.all()
            context['files'] = [{
                'id': doc.id,
                'name': doc.name,
                'uploaded_at': doc.uploaded_at,
                'size': format_file_size(doc.file.size if doc.file else 0)
            } for doc in documents]

        elif action == 'read':
            doc_id = request.GET.get('id')
            if not doc_id or not doc_id.isdigit():
                context['error'] = 'Valid document ID required'
            else:
                return redirect('serve_document', document_id=doc_id)

        elif action == 'create' and request.method == 'POST':
            if 'file' not in request.FILES:
                context['error'] = 'No file provided'
            else:
                name = request.POST.get('name', '').strip()
                if not name:
                    context['error'] = 'Name required'
                else:
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)

                    valid, error = validate_file(uploaded_file, [
                        'application/pdf', 'text/plain', 'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    ])
                    if not valid:
                        context['error'] = error
                    else:
                        with transaction.atomic():
                            DocumentAsset.objects.create(
                                file=uploaded_file,
                                name=name[:255]
                            )
                        try:
                            log_asset_access(request.user, 'documents', name, 'create', request, True, is_mfa_verified(request, request.user)[0])
                        except Exception as log_error:
                            import logging
                            logging.error(f"Failed to log document creation: {str(log_error)}")
                        return redirect('documents')

        elif action == 'write' and request.method == 'POST':
            doc_id = request.POST.get('id')
            if not doc_id or not doc_id.isdigit() or 'file' not in request.FILES:
                context['error'] = 'Valid document ID and file required'
            else:
                try:
                    document = DocumentAsset.objects.get(id=doc_id)
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)

                    valid, error = validate_file(uploaded_file, [
                        'application/pdf', 'text/plain', 'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    ])
                    if not valid:
                        context['error'] = error
                    else:
                        document.file = uploaded_file
                        document.save()
                        
                        try:
                            log_asset_access(request.user, 'documents', document.name, 'write', request, True, is_mfa_verified(request, request.user)[0])
                        except Exception as log_error:
                            import logging
                            logging.error(f"Failed to log document update: {str(log_error)}")
                        return redirect('documents')
                except DocumentAsset.DoesNotExist:
                    context['error'] = 'Document not found'
                except Exception as e:
                    context['error'] = f'Error updating document: {str(e)}'
                    import logging
                    logging.error(f"Document write error: {str(e)}")

        elif action == 'delete' and request.method == 'POST':
            doc_id = request.POST.get('id')
            if not doc_id or not doc_id.isdigit():
                context['error'] = 'Valid document ID required'
            else:
                try:
                    document = DocumentAsset.objects.get(id=doc_id)
                    doc_name = document.name
                    if document.file:
                        document.file.delete()
                    document.delete()
                    try:
                        log_asset_access(request.user, 'documents', doc_name, 'delete', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log document delete: {str(log_error)}")
                    return redirect('documents')
                except DocumentAsset.DoesNotExist:
                    context['error'] = 'Document not found'

    except Exception as e:
        context['error'] = "An error occurred."
        import logging
        logging.error(f"Documents view error: {str(e)}")

    if not context.get('error'):
        documents = DocumentAsset.objects.all()
        context['files'] = [{
            'id': doc.id,
            'name': doc.name,
            'uploaded_at': doc.uploaded_at,
            'size': format_file_size(doc.file.size if doc.file else 0)
        } for doc in documents]

    context['user_permissions'] = user_permissions
    return render(request, 'assets/documents.html', context)


@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def confidential_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None, 'view_content': None, 'view_name': None}

    try:
        lizard = request.user.lizards
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
    except:
        user_permissions = {}

    if not check_access(request.user, 'confidential', action):
        mfa_ok, _ = is_mfa_verified(request, request.user)
        try:
            log_asset_access(request.user, 'confidential', 'unknown', action, request, False, mfa_ok)
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log denied confidential access: {str(log_error)}")
        context['user_permissions'] = user_permissions
        return render(request, 'base/forbidden.html', context)

    mfa_ok, _ = is_mfa_verified(request, request.user)
    if not mfa_ok:
        context['error'] = 'MFA verification required for confidential access'
        return render(request, 'base/forbidden.html', context)

    try:
        if action == 'list':
            confidential_files = ConfidentialAsset.objects.all()
            context['files'] = [{
                'id': conf.id,
                'name': conf.name,
                'uploaded_at': conf.uploaded_at,
                'size': format_file_size(conf.encrypted_file.size if conf.encrypted_file else 0)
            } for conf in confidential_files]

        elif action == 'read':
            conf_id = request.GET.get('id')
            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    encrypted_content = confidential.encrypted_file.read()
                    decrypted_content = FERNET.decrypt(encrypted_content).decode('utf-8')
                    context['view_content'] = decrypted_content
                    context['view_name'] = confidential.name
                    try:
                        log_asset_access(request.user, 'confidential', confidential.name, 'read', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log confidential read: {str(log_error)}")
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'
                except Exception as e:
                    context['error'] = 'Error decrypting file'

        elif action == 'create' and request.method == 'POST':
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '')

            if not name:
                context['error'] = 'Name required'
            elif len(content) > 1024 * 1024:
                context['error'] = 'Content too large'
            else:
                try:
                    name = sanitize_filename(name)[:255]
                    encrypted_content = FERNET.encrypt(content.encode('utf-8'))
                    encrypted_file = ContentFile(encrypted_content, name=f"{name}.enc")

                    ConfidentialAsset.objects.create(
                        encrypted_file=encrypted_file,
                        name=name,
                        encryption_metadata='Fernet AES-128'
                    )
                    try:
                        log_asset_access(request.user, 'confidential', name, 'create', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log confidential create: {str(log_error)}")
                    return redirect('confidential')
                except Exception as e:
                    context['error'] = 'Error creating confidential file'

        elif action == 'write' and request.method == 'POST':
            conf_id = request.POST.get('id')
            content = request.POST.get('content', '')

            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            elif len(content) > 1024 * 1024:
                context['error'] = 'Content too large'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    encrypted_content = FERNET.encrypt(content.encode('utf-8'))

                    confidential.encrypted_file = ContentFile(encrypted_content, name=f"{confidential.name}.enc")
                    confidential.save()

                    try:
                        log_asset_access(request.user, 'confidential', confidential.name, 'write', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log confidential write: {str(log_error)}")
                    return redirect('confidential')
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'
                except Exception as e:
                    context['error'] = 'Error updating confidential file'

        elif action == 'delete' and request.method == 'POST':
            conf_id = request.POST.get('id')
            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    conf_name = confidential.name
                    if confidential.encrypted_file:
                        confidential.encrypted_file.delete()
                    confidential.delete()
                    try:
                        log_asset_access(request.user, 'confidential', conf_name, 'delete', request, True, is_mfa_verified(request, request.user)[0])
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log confidential delete: {str(log_error)}")
                    return redirect('confidential')
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'

    except Exception as e:
        context['error'] = "An error occurred."
        import logging
        logging.error(f"Confidential view error: {str(e)}")

    confidential_files = ConfidentialAsset.objects.all()
    context['files'] = [{
        'id': conf.id,
        'name': conf.name,
        'uploaded_at': conf.uploaded_at,
        'size': format_file_size(conf.encrypted_file.size if conf.encrypted_file else 0)
    } for conf in confidential_files]

    context['user_permissions'] = user_permissions
    return render(request, 'assets/confidential.html', context)


@login_required
@csrf_protect
@never_cache
def serve_image(request, image_id):
    try:
        image = ImageAsset.objects.get(id=image_id)

        if not check_access(request.user, 'images', 'read'):
            try:
                log_asset_access(request.user, 'images', image.name, 'read', request, False, is_mfa_verified(request, request.user)[0])
            except Exception as log_error:
                import logging
                logging.error(f"Failed to log denied image access: {str(log_error)}")
            raise Http404("Access denied")

        try:
            log_asset_access(request.user, 'images', image.name, 'read', request, True, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log successful image access: {str(log_error)}")

        if not image.file:
            raise Http404("Image file not found")

        try:
            image.file.seek(0)
            file_content = image.file.read()
        except Exception:
            raise Http404("Error reading image file")

        valid_image, _ = validate_file_signature(file_content[:1024], ['image/jpeg', 'image/png', 'image/gif'])
        if not valid_image:
            raise Http404("Invalid image file")

        file_hash = hashlib.sha256(file_content).hexdigest()

        response = HttpResponse(
            file_content,
            content_type=mimetypes.guess_type(image.name)[0] or 'application/octet-stream'
        )

        safe_filename = sanitize_filename(image.name)
        response['Content-Disposition'] = f'inline; filename="{safe_filename}"'
        response['X-Content-Hash'] = file_hash
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'

        return response

    except ImageAsset.DoesNotExist:
        raise Http404("Image not found")


@login_required
@csrf_protect
@never_cache
def serve_document(request, document_id):
    try:
        document = DocumentAsset.objects.get(id=document_id)

        if not check_access(request.user, 'documents', 'read'):
            try:
                log_asset_access(request.user, 'documents', document.name, 'read', request, False, is_mfa_verified(request, request.user)[0])
            except Exception as log_error:
                import logging
                logging.error(f"Failed to log denied document access: {str(log_error)}")
            raise Http404("Access denied")

        try:
            log_asset_access(request.user, 'documents', document.name, 'read', request, True, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log successful document access: {str(log_error)}")

        if not document.file:
            raise Http404("Document file not found")

        try:
            document.file.seek(0)
            file_content = document.file.read()
        except Exception:
            raise Http404("Error reading document file")

        allowed_doc_types = [
            'application/pdf',
            'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]

        valid_doc, _ = validate_file_signature(file_content[:1024], allowed_doc_types)
        if not valid_doc:
            raise Http404("Invalid document file type")

        file_hash = hashlib.sha256(file_content).hexdigest()

        response = HttpResponse(
            file_content,
            content_type=mimetypes.guess_type(document.name)[0] or 'application/octet-stream'
        )

        safe_filename = sanitize_filename(document.name)
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        response['X-Content-Hash'] = file_hash
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'

        return response

    except DocumentAsset.DoesNotExist:
        raise Http404("Document not found")


@login_required
@csrf_protect
def image_preview(request, image_id):

    try:
        image = get_object_or_404(ImageAsset, id=image_id)

        if not check_access(request.user, 'images', 'read'):
            try:
                log_asset_access(request.user, 'images', image.name, 'preview', request, False, is_mfa_verified(request, request.user)[0])
            except Exception as log_error:
                import logging
                logging.error(f"Failed to log denied image preview: {str(log_error)}")
            return render(request, 'base/forbidden.html')

        try:
            log_asset_access(request.user, 'images', image.name, 'preview', request, True, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log successful image preview: {str(log_error)}")

        return render(request, 'assets/image_view.html', {'image': image})

    except Exception:
        return render(request, 'base/forbidden.html')
