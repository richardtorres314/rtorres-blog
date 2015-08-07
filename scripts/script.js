$(document).ready(function() {
	var $text;
	$('.circle').mouseenter(function() {
		$(this).transition({rotateY: '180deg'});
		$text = $(this).text();
		$(this).text('');
	});
	
	$('.circle').mouseleave(function() {
		$(this).transition({rotateY: '0deg'});
		$(this).text($text);
	});
	
	$('a').attr('draggable', 'false');
});